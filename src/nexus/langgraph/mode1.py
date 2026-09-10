"""Mode 1 — Examiner-Led Query Desk.

The examiner drives. The LLM is a thin scribe:
1. NL -> needles: translate English question into search terms + time window
2. N4 query: code search (no LLM in the search)
3. Examiner selects hits -> promote to DRAFT skeleton (examiner is the writer)
4. LLM scribe: format the DRAFT with RAG methodology context
5. Examiner reviews -> HMAC -> report (existing flow)

The LLM never chooses which hits become findings. The examiner selects.
The LLM never approves. The examiner HMACs.
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

_NL_TO_NEEDLES_SYSTEM = """\
You are a DFIR search-term extractor. The examiner asks a question in English.
Your job is to extract concrete search needles (terms that would appear in
parsed CSV/JSON output from forensic tools like Hayabusa, EvtxECmd, PECmd,
MFTECmd, RECmd, etc.) and a time window if mentioned.

Rules:
- Return ONLY a JSON object: {"needles": ["term1","term2",...], "window": "start..end" or "", "rationale": "one sentence"}
- Needles are concrete strings that appear in log rows: tool names, file
  extensions, event IDs, process names, registry keys, IP patterns.
- Do NOT return prose. Do NOT return methodology. Do NOT return full sentences.
- If the question mentions a time range, extract it as "YYYY-MM-DD..YYYY-MM-DD".
- If no time range is mentioned, set window to "".
- Include 3-10 needles. Too few misses hits; too many floods the query.
- When case context is provided (evidence families present, playbook terms,
  RAG methodology, already-searched needles), ground your needles in it:
  prefer the playbook/RAG vocabulary, do not repeat already-searched needles,
  and prioritise identifiers the examiner actually named.
- Common needle patterns: sdelete, .pst, USBSTOR, wevtutil, 1102 (log clear),
  mimikatz, lsass, psexec, encodedcommand, powershell, cmd.exe, rundll32,
  mshta, wscript, schtasks, reg add, net user, 4624, 4625, 4648, 4672, 4720.

Examples:
Question: "Did anyone clear the security event logs around August 10-15?"
Output: {"needles": ["wevtutil","1102","cleared","audit","security"],"window": "2026-08-10..2026-08-15","rationale": "Log-clear artifacts"}

Question: "Was sdelete used to wipe files?"
Output: {"needles": ["sdelete","Sysinternals","delete","wipe","fileoverwrite"],"window": "","rationale": "Wipe-tool traces"}

Question: "Any evidence of credential dumping via mimikatz or LSASS access?"
Output: {"needles": ["mimikatz","lsass","sekurlsa","credential","dump","00000001.log"],"window": "","rationale": "Credential-dump artifacts"}
"""


# ---------------------------------------------------------------------------
# Deterministic entity extraction (Phase 4g): the examiner's own identifiers
# are the highest-signal needles and must survive even without an LLM.
# ---------------------------------------------------------------------------

_ENTITY_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("url", re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)),
    ("email", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    ("sha256", re.compile(r"\b[a-fA-F0-9]{64}\b")),
    ("sha1", re.compile(r"\b[a-fA-F0-9]{40}\b")),
    ("md5", re.compile(r"\b[a-fA-F0-9]{32}\b")),
    ("windows_path", re.compile(r"(?:[A-Za-z]:\\|\\\\)[^\s\"'<>|]+")),
    ("posix_path", re.compile(r"/[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+){2,}")),
    ("domain_user", re.compile(r"\b[A-Za-z][A-Za-z0-9._-]{1,31}\\[A-Za-z0-9._$-]{1,64}\b")),
    ("ipv4", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
    ("domain", re.compile(r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,}\b")),
]

_ENTITY_TRAILING = ").,;:!?]}>'\""
_ENTITY_NEEDLE_ORDER = (
    "sha256", "sha1", "md5", "windows_path", "posix_path",
    "url", "email", "domain_user", "ipv4", "domain",
)


def extract_entities(text: str) -> dict[str, list[str]]:
    """Extract identifiers named in the examiner's question.

    Deterministic and LLM-independent: IPs, domains, URLs, emails, hashes,
    Windows/POSIX paths, and ``DOMAIN\\user`` accounts.
    """
    text = text or ""
    out: dict[str, list[str]] = {kind: [] for kind, _ in _ENTITY_PATTERNS}
    seen: set[str] = set()
    for kind, rx in _ENTITY_PATTERNS:
        for raw in rx.findall(text):
            value = str(raw).rstrip(_ENTITY_TRAILING)
            key = value.lower()
            if not value or key in seen:
                continue
            seen.add(key)
            if len(out[kind]) < 8:
                out[kind].append(value)
    return {kind: values for kind, values in out.items() if values}


def entities_to_needles(entities: dict[str, list[str]] | None) -> list[str]:
    """Entity needles, exact identifiers first (specific -> broad)."""
    if not entities:
        return []
    needles: list[str] = []
    for kind in _ENTITY_NEEDLE_ORDER:
        needles.extend(entities.get(kind) or [])
    return needles


def _dedupe_needles(items: list[str], cap: int = 14) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        value = str(item).strip()
        key = value.lower()
        if not value or key in seen:
            continue
        seen.add(key)
        out.append(value)
    return out[:cap]


def _context_block(context: dict[str, Any] | None) -> str:
    """Render case context for the scribe prompt (WP 4g-A)."""
    if not context:
        return ""
    lines: list[str] = []
    families = [str(f) for f in (context.get("families") or []) if str(f).strip()]
    if families:
        lines.append(f"Evidence families present: {', '.join(families[:24])}")
    terms = [str(t) for t in (context.get("playbook_terms") or []) if str(t).strip()]
    if terms:
        lines.append("Playbook search terms for these families: " + ", ".join(terms[:60]))
    searched = [str(s) for s in (context.get("searched") or []) if str(s).strip()]
    if searched:
        lines.append("Already searched (do not repeat): " + ", ".join(searched[:30]))
    playbook_context = str(context.get("playbook_context") or "").strip()
    if playbook_context:
        lines.append("Playbook methodology and caveats:\n" + playbook_context[:1800])
    attack_context = str(context.get("attack_context") or "").strip()
    if attack_context:
        lines.append(
            "MITRE ATT&CK packs for this case (terms + false-positive caveats):\n"
            + attack_context[:1800]
        )
    rag = str(context.get("rag") or "").strip()
    if rag:
        lines.append("RAG methodology:\n" + rag[:1200])
    intake = context.get("intake") or {}
    if isinstance(intake, dict):
        for key in ("question", "subjects", "hypothesis"):
            value = str(intake.get(key) or "").strip()
            if value:
                lines.append(f"Case {key}: {value[:400]}")
    if not lines:
        return ""
    return (
        "\n\nContext (use it; prefer needles grounded in this material):\n"
        + "\n".join(lines)
        + "\n"
    )


def nl_to_needles(
    question: str,
    model: Any = None,
    context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Translate an English question into search needles + time window.

    ``context`` (WP 4g) grounds the scribe: evidence families present,
    playbook terms/caveats for those families, RAG methodology, already
    searched needles, and the case intake. Deterministic entity needles
    (IPs, domains, hashes, paths, accounts) always survive, LLM or not.

    If no model is provided, falls back to keyword extraction (no LLM).
    Returns {"needles": [...], "window": "...", "source": "llm"|"heuristic",
    "entities": {...}, "rationale": "..."}.
    """
    question = (question or "").strip()
    if not question:
        return {"needles": [], "window": "", "source": "none", "error": "empty question"}

    entities = extract_entities(question)
    entity_needles = entities_to_needles(entities)
    attack_needles = [
        str(t) for t in (context or {}).get("attack_needles") or [] if str(t).strip()
    ]

    if model is None:
        result = _heuristic_needles(question)
        result["needles"] = _dedupe_needles(
            entity_needles + list(result.get("needles") or []) + attack_needles
        )
        result["entities"] = entities
        return result

    try:
        response = model.invoke([
            {"role": "system", "content": _NL_TO_NEEDLES_SYSTEM},
            {
                "role": "user",
                "content": f"Question: {question}{_context_block(context)}\nOutput:",
            },
        ])
        text = getattr(response, "content", str(response))
        parsed = _parse_json_response(text)
        if parsed and isinstance(parsed.get("needles"), list):
            llm_needles = [str(n).strip() for n in parsed["needles"] if str(n).strip()]
            needles = _dedupe_needles(entity_needles + llm_needles, cap=10)
            needles = _dedupe_needles(needles + attack_needles, cap=14)
            window = str(parsed.get("window") or "").strip()
            if needles:
                return {
                    "needles": needles,
                    "window": window,
                    "source": "llm",
                    "rationale": str(parsed.get("rationale") or "")[:500],
                    "entities": entities,
                }
        log.warning("LLM returned unparseable needles, falling back to heuristic")
    except Exception as exc:
        log.warning("LLM needles failed (%s), falling back to heuristic", exc)

    result = _heuristic_needles(question)
    result["needles"] = _dedupe_needles(
        entity_needles + list(result.get("needles") or []) + attack_needles
    )
    result["entities"] = entities
    return result


def _heuristic_needles(question: str) -> dict[str, Any]:
    """Extract needles from English without an LLM (keyword matching)."""
    q = question.lower()
    needles: list[str] = []
    _KNOWN_TERMS = [
        "sdelete", "wevtutil", "1102", "mimikatz", "lsass", "sekurlsa",
        "psexec", "psexesvc", "encodedcommand", "powershell", "rundll32",
        "mshta", "wscript", "cscript", "schtasks", "reg add", "net user",
        "net localgroup", "USBSTOR", ".pst", ".ost", "googledrive", "drivefs",
        "4624", "4625", "4648", "4672", "4720", "4728", "4732", "4756",
        "cleared", "audit", "security", "prefetch", "amcache", "shellbags",
        "lnk", "jumplist", "srum", "bits", "usnjrnl", "mft",
        "autorun", "persistence", "scheduled task", "service",
        "cmd.exe", "conhost", "werfault",
    ]
    for term in _KNOWN_TERMS:
        if term.lower() in q:
            needles.append(term)
    if not needles:
        import re
        tokens = re.findall(r"\b[a-z0-9_.]{4,}\b", q)
        _STOP = {
            "what", "when", "where", "which", "there", "their", "about",
            "would", "could", "should", "evidence", "anyone", "someone",
            "around", "between", "during", "before", "after", "show",
            "find", "look", "search", "check", "tell", "give", "list",
        }
        needles = [t for t in tokens if t not in _STOP][:8]

    import re
    # Try "YYYY-MM-DD..YYYY-MM-DD", "between X and Y", "X to Y", "X through Y"
    date_match = re.search(
        r"(\d{4}-\d{2}-\d{2})\s*(?:to|through|..|until|-|and|through)\s*(\d{4}-\d{2}-\d{2})",
        question,
    )
    window = ""
    if date_match:
        window = f"{date_match.group(1)}..{date_match.group(2)}"

    return {"needles": needles, "window": window, "source": "heuristic"}


def _parse_json_response(text: str) -> dict | None:
    """Extract a JSON object from an LLM text response."""
    import re
    text = text.strip()
    if text.startswith("{") and text.endswith("}"):
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass
    m = re.search(r"\{[^{}]*\}", text, re.DOTALL)
    if m:
        try:
            return json.loads(m.group(0))
        except json.JSONDecodeError:
            pass
    return None


_SCRIBE_SYSTEM = """\
You are a DFIR finding scribe. The examiner has selected N4 query hits and
created a DRAFT finding skeleton. Your job is to format it properly using
RAG methodology context — NOT to invent new facts.

Rules:
- You receive the DRAFT skeleton (title, selected hits with audit_ids).
- You receive RAG methodology notes (how to read the artifact type).
- You fill in: observation (one-sentence summary of the hits),
  interpretation (under the examiner's hypothesis), confidence +
  confidence_justification, and MITRE ATT&CK IDs if justified by the hits.
- You do NOT add new evidence rows. You do NOT invent timestamps, hosts,
  or IOCs that are not in the selected hits.
- You do NOT change the title or the audit_ids.
- Return ONLY a JSON object with the fields to update:
  {"observation": "...", "interpretation": "...", "confidence": "LOW|MEDIUM|HIGH",
   "confidence_justification": "...", "mitre_ids": ["T1234"], "type": "finding|execution|..."}
- If the hits are insufficient for a confident interpretation, set confidence
  to LOW and explain what is missing in confidence_justification.
"""


def scribe_finding(
    draft: dict[str, Any],
    hits: list[dict[str, Any]],
    rag_context: str = "",
    model: Any = None,
) -> dict[str, Any]:
    """LLM scribe: format a DRAFT finding with RAG methodology.

    The examiner has selected hits and created a skeleton. The scribe fills
    in observation, interpretation, confidence, and MITRE IDs — using ONLY
    the provided hits and RAG methodology. No new facts.

    Returns the updated finding dict (merged with scribe output).
    """
    if model is None:
        return _heuristic_scribe(draft, hits)

    hit_rows = []
    for h in hits[:20]:
        hit_rows.append({
            "family": h.get("family", ""),
            "file": h.get("file", ""),
            "line": h.get("line", ""),
            "text": str(h.get("text", ""))[:500],
            "terms": h.get("terms", []),
        })

    families = {h.get("family", "") for h in hits if h.get("family")}
    if not rag_context:
        rag_context = _rag_methodology_for_families(families)

    user_msg = (
        f"DRAFT skeleton:\n{json.dumps(draft, indent=2, default=str)[:2000]}\n\n"
        f"Selected hits (ONLY source of facts):\n{json.dumps(hit_rows, indent=2, default=str)[:4000]}\n\n"
        f"RAG methodology:\n{rag_context[:2000] or '(none)'}\n\n"
        f"Fill in the finding fields. Return JSON only."
    )

    try:
        response = model.invoke([
            {"role": "system", "content": _SCRIBE_SYSTEM},
            {"role": "user", "content": user_msg},
        ])
        text = getattr(response, "content", str(response))
        parsed = _parse_json_response(text)
        if parsed and isinstance(parsed, dict):
            merged = dict(draft)
            for k in ("observation", "interpretation", "confidence",
                       "confidence_justification", "mitre_ids", "type"):
                if parsed.get(k):
                    merged[k] = parsed[k]
            merged["scribe_source"] = "llm"
            return merged
        log.warning("Scribe returned unparseable JSON, using heuristic")
    except Exception as exc:
        log.warning("Scribe LLM failed (%s), using heuristic", exc)

    return _heuristic_scribe(draft, hits)


def _rag_methodology_for_families(families: set[str]) -> str:
    """Gather RAG methodology context for the artifact families in hits.

    Uses the local RAG index (ChromaDB) to find methodology for reading
    each artifact type (e.g. Prefetch, EVTX, LNK, SRUM). Returns a concise
    text block to pass to the scribe. If RAG is not available, returns the
    family list as minimal context.
    """
    if not families:
        return ""
    try:
        from nexus.tools.rag import _check_rag_available, _get_index

        available, _ = _check_rag_available()
        if not available:
            return "Artifact families: " + ", ".join(sorted(families))

        idx = _get_index()
        blocks: list[str] = []
        seen: set[str] = set()
        for fam in sorted(families):
            if not fam or fam in seen:
                continue
            seen.add(fam)
            # Search for methodology on how to read this artifact
            q = f"how to interpret forensic {fam} evidence"
            try:
                result = idx.search(query=q, top_k=3, source="kape")
                docs = result.get("results", [])
                if not docs:
                    # Fallback: search without source filter
                    result = idx.search(query=q, top_k=2)
                    docs = result.get("results", [])
                if docs:
                    block = f"\n--- {fam} ---\n"
                    for d in docs[:3]:
                        text = d.get("text") or d.get("document") or ""
                        block += str(text)[:400] + "\n"
                    blocks.append(block)
            except Exception:
                blocks.append(f"\n--- {fam} ---\n(no RAG methodology available)\n")
        return "\n".join(blocks).strip() or "Artifact families: " + ", ".join(sorted(families))
    except Exception as exc:
        log.warning("RAG methodology lookup failed: %s", exc)
        return "Artifact families: " + ", ".join(sorted(families))


def _heuristic_scribe(draft: dict[str, Any], hits: list[dict[str, Any]]) -> dict[str, Any]:
    """Format a finding without an LLM (basic structuring from hits)."""
    merged = dict(draft)
    if not merged.get("observation") and hits:
        families = sorted({h.get("family", "?") for h in hits})
        merged["observation"] = (
            f"{len(hits)} hit(s) across {', '.join(families)} matching "
            f"examiner-selected needles."
        )
    if not merged.get("interpretation"):
        merged["interpretation"] = (
            "Examiner-selected hit set pending interpretation. "
            "Review the evidence rows and provide an interpretation "
            "under the case hypothesis."
        )
    if not merged.get("confidence"):
        merged["confidence"] = "LOW"
    if not merged.get("confidence_justification"):
        merged["confidence_justification"] = (
            "Auto-staged from examiner hit selection. "
            "Confidence pending corroboration review."
        )
    if not merged.get("type"):
        merged["type"] = "finding"
    merged["scribe_source"] = "heuristic"
    return merged


def promote_hits_to_draft(
    case_dir: Path,
    hits: list[dict[str, Any]],
    title: str,
    examiner: str = "",
    interpretation_hint: str = "",
    examiner_selected: bool = True,
) -> dict[str, Any]:
    """Promote hits to a DRAFT finding skeleton.

    ``examiner_selected=True`` (Mode 1): the examiner picked the hits.
    ``examiner_selected=False`` marks an LLM-proposed finding (Mode 2) —
    the draft is still examiner-gated for approval either way.

    Returns the DRAFT finding dict (not yet written to findings.json).
    """
    evidence_rows = []
    for h in hits:
        # n4_hits does not emit a time field — parse the first timestamp
        # from the raw row text so evidence rows carry a usable time.
        hit_time = h.get("time") or ""
        if not hit_time:
            try:
                from nexus.langgraph.query_pack import _DATE_RE
                m = _DATE_RE.search(str(h.get("text", "")))
                if m:
                    hit_time = m.group(1) + (f"T{m.group(2)}" if m.group(2) else "")
            except Exception:
                pass
        row = {
            "time": hit_time,
            "source": f"{h.get('family', '')}/{h.get('file', '')}",
            "artifact": h.get("file", ""),
            "detail": str(h.get("text", ""))[:500],
        }
        evidence_rows.append(row)

    # Resolve audit_ids from the ledger by matching hit families to tool names
    audit_ids: list[str] = []
    try:
        import json as _json

        from nexus.langgraph.pipeline_runs import resolve_tools_extractions
        extractions = resolve_tools_extractions(case_dir)
        ledger_path = extractions / "_tool_lane_ledger.json"
        if not ledger_path.is_file():
            ledger_path = extractions.parent / "ledger" / "_tool_lane_ledger.json"
        if ledger_path.is_file():
            ledger = _json.loads(ledger_path.read_text(encoding="utf-8"))
            from nexus.langgraph.query_pack import _audits_for_families
            families = {h.get("family", "") for h in hits if h.get("family")}
            audit_ids = _audits_for_families(ledger, families)
    except Exception as exc:
        log.warning("Could not resolve audit_ids from ledger: %s", exc)

    draft = {
        "title": title,
        "observation": "",  # scribe fills this
        "interpretation": interpretation_hint,
        "confidence": "LOW",
        "confidence_justification": "",
        "type": "finding",
        "audit_ids": audit_ids,
        "evidence": evidence_rows[:12],
        "host": "",
        "event_timestamp": hits[0].get("time", "") if hits else "",
        "status": "DRAFT",
        "examiner_selected": examiner_selected,
    }
    return draft


def save_draft_finding(case_dir: Path, draft: dict[str, Any]) -> dict[str, Any]:
    """Write a DRAFT finding to findings.json and return the staged result."""
    from nexus.case_manager import CaseManager

    mgr = CaseManager()
    # Pass the target case explicitly — the global active-case pointer may
    # point at a different case, and record_finding's active-case resolution
    # never reads private attributes.
    result = mgr.record_finding(draft, audit=None, case_dir=case_dir)
    return result
