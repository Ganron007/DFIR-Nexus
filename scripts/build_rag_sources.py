"""Generate local RAG JSONL sources from our compiled framework registries.

Net-new content only (verified against the downloaded bundle):
- ITM v2.13 sections + subsections (the bundle has none),
- MITRE ATT&CK v19 **detection strategies + analytics** (the bundle predates
  them; its technique docs are untouched),
- MITRE ATLAS techniques + mitigations (bundle has case studies only),
- MBC capa/YARA rule mappings per behavior (the bundle's MBC docs are thin and
  carry no rule references).

Writes ``RAGDocument``-schema JSONL into a local folder (default
``~/.nexus/data/rag/sources/local``) plus ``_manifest.json`` with counts,
registry versions and registry file hashes for provenance. Then:

    python scripts/build_rag_sources.py
    -> forensic_rag_rebuild()   (embeds into the local delta collection)

Nothing here is committed to the repo: generated JSONL derives from local
registries and lives in the user data dir.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))


def _default_out() -> Path:
    """Follow the same data root the RAG index uses (config-aware)."""
    from nexus.config import settings

    return settings.data_root / "rag" / "sources" / "local"


DEFAULT_OUT = _default_out()
MODEL_EXPECTED = "BAAI/bge-base-en-v1.5"
MAX_TEXT = 1800


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()[:16]


def _doc(doc_id: str, text: str, source: str, title: str, **meta) -> dict:
    return {
        "id": doc_id,
        "text": text.strip()[:MAX_TEXT],
        "source": source,
        "title": title,
        "technique_id": str(meta.get("mitre_techniques") or ""),
        "platform": str(meta.get("platform") or ""),
        "metadata": {k: v for k, v in meta.items() if v not in (None, "", [], {})},
    }


def build_itm() -> list[dict]:
    from nexus.knowledge.loader import get_itm_registry

    docs: list[dict] = []
    for article in get_itm_registry().get("articles") or []:
        stage = str(article.get("title") or "")
        for section in article.get("sections") or []:
            sid = f"{article.get('id')}/{section.get('id')}"
            subs = [
                str(s.get("title"))
                for s in (section.get("subsections") or [])[:8]
                if s.get("title")
            ]
            dets = [
                str(d.get("title"))
                for d in (section.get("detections") or [])[:6]
                if d.get("title")
            ]
            prevs = [
                str(p.get("title"))
                for p in (section.get("preventions") or [])[:6]
                if p.get("title")
            ]
            text = (
                f"Insider Threat Matrix: {section.get('title')} "
                f"ID: {sid} Stage: {stage}\n"
                f"Description: {section.get('description') or '(none)'}\n"
                + (f"Subsections: {', '.join(subs)}\n" if subs else "")
                + (f"Detections: {', '.join(dets)}\n" if dets else "")
                + (f"Preventions: {', '.join(prevs)}\n" if prevs else "")
            ).strip()
            docs.append(_doc(
                f"itm:{sid}", text, "itm", str(section.get("title") or sid),
                itm_id=sid, stage=stage,
                platform=",".join(section.get("platforms") or []),
            ))
            for sub in section.get("subsections") or []:
                sub_id = str(sub.get("id") or "")
                if not sub_id:
                    continue
                # Canonical form matches the registry index (article/short-id).
                sub_full = f"{article.get('id')}/{sub_id}"
                sub_text = (
                    f"Insider Threat Matrix: {sub.get('title')} "
                    f"ID: {sub_full} (under {sid} {section.get('title')}) "
                    f"Stage: {stage}"
                )
                docs.append(_doc(
                    f"itm:{sub_full}", sub_text, "itm",
                    str(sub.get("title") or sub_id),
                    itm_id=sub_full, stage=stage, parent=sid,
                    platform=",".join(section.get("platforms") or []),
                ))
    return docs


def build_attack_detections() -> list[dict]:
    from nexus.knowledge.loader import get_attack_registry

    registry = get_attack_registry()
    names = {t.get("id"): t.get("name") for t in registry.get("techniques") or []}
    docs: list[dict] = []
    for tech in registry.get("techniques") or []:
        tid = str(tech.get("id") or "")
        for strategy in tech.get("detection") or []:
            det_id = str(strategy.get("id") or "")
            if not det_id:
                continue
            analytics = []
            platforms: set[str] = set()
            logs: set[str] = set()
            for analytic in strategy.get("analytics") or []:
                platforms.update(str(a) for a in (analytic.get("platforms") or []))
                logs.update(str(x) for x in (analytic.get("log_sources") or []))
                block = " ".join(x for x in (
                    str(analytic.get("name") or ""),
                    str(analytic.get("description") or ""),
                ) if x)
                if block:
                    analytics.append(block)
            tactics = ", ".join(str(t) for t in (tech.get("tactics") or []))
            text = (
                f"MITRE ATT&CK Detection Strategy: {strategy.get('name')} "
                f"ID: {det_id}\n"
                f"Technique: {tid} {names.get(tid) or tech.get('name') or ''}"
                + (f" (tactics: {tactics})" if tactics else "")
                + "\n"
                + (f"Analytics: {' | '.join(analytics[:3])}\n" if analytics else "")
                + (f"Log sources: {', '.join(sorted(logs)[:6])}" if logs else "")
            ).strip()
            docs.append(_doc(
                f"attack-det:{det_id}", text, "attack_detections",
                f"{det_id} {strategy.get('name')}", detection_id=det_id,
                mitre_techniques=tid,
                platform=",".join(sorted(platforms)),
            ))
    return docs


def build_atlas() -> list[dict]:
    from nexus.knowledge.loader import get_atlas_registry

    registry = get_atlas_registry()
    docs: list[dict] = []
    for tech in registry.get("techniques") or []:
        tid = str(tech.get("id") or "")
        refs = ",".join(str(r.get("id") or "") for r in (tech.get("attack_refs") or []))
        tactics = ", ".join(str(t) for t in (tech.get("tactics") or []))
        text = (
            f"MITRE ATLAS Technique: {tech.get('name')} ID: {tid} "
            f"({tech.get('maturity') or 'n/a'})\n"
            + (f"Tactics: {tactics}\n" if tactics else "")
            + (f"Description: {tech.get('description')}\n" if tech.get("description") else "")
            + (f"Related ATT&CK: {refs}" if refs else "")
        ).strip()
        docs.append(_doc(
            f"atlas:{tid}", text, "mitre_atlas_techniques",
            f"{tid} {tech.get('name')}", atlas_id=tid, mitre_techniques=refs,
        ))
    for mitigation in registry.get("mitigations") or []:
        mid = str(mitigation.get("id") or "")
        text = (
            f"MITRE ATLAS Mitigation: {mitigation.get('name')} ID: {mid}\n"
            f"Category: {mitigation.get('category') or ''} "
            f"ML lifecycle: {', '.join(mitigation.get('ml_lifecycle') or [])}\n"
            f"Description: {mitigation.get('description') or ''}"
        ).strip()
        docs.append(_doc(
            f"atlas-mit:{mid}", text, "mitre_atlas_mitigations",
            f"{mid} {mitigation.get('name')}", atlas_id=mid,
        ))
    return docs


def build_mbc_capa() -> list[dict]:
    from nexus.knowledge.loader import get_mbc_registry

    docs: list[dict] = []
    for behavior in get_mbc_registry().get("behaviors") or []:
        rules = [
            str(r.get("rule_name") or "")
            for r in (behavior.get("detection_rules") or [])
            if r.get("rule_name")
        ]
        if not rules:
            continue
        bid = str(behavior.get("id") or "")
        methods = [
            f"{m.get('id')} {m.get('name')}"
            for m in (behavior.get("methods") or [])[:6]
        ]
        text = (
            f"MBC Malware Behavior: {behavior.get('name')} ID: {bid}\n"
            f"Description: {behavior.get('description') or '(none)'}\n"
            f"capa/YARA rules ({len(rules)}): {', '.join(rules[:10])}\n"
            + (f"Methods: {'; '.join(methods)}\n" if methods else "")
            + (f"Families: {', '.join((behavior.get('families') or [])[:6])}"
               if behavior.get("families") else "")
        ).strip()
        docs.append(_doc(
            f"mbc-capa:{bid}", text, "mbc_capa",
            f"{bid} {behavior.get('name')}", mbc_id=bid, rule_count=len(rules),
        ))
    return docs


BUILDERS = {
    "itm": ("itm.jsonl", build_itm, "itm/itm_registry.yaml"),
    "attack_detections": ("attack_detections.jsonl", build_attack_detections,
                          "attack/attack_registry.yaml"),
    "atlas": ("atlas_techniques.jsonl", build_atlas, "atlas/atlas_registry.yaml"),
    "mbc_capa": ("mbc_capa.jsonl", build_mbc_capa, "mbc/mbc_registry.yaml"),
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--only", default="", help="comma list of builders")
    args = parser.parse_args()

    from nexus.knowledge.loader import _find_data_dir

    data_dir = _find_data_dir()
    only = {s.strip() for s in args.only.split(",") if s.strip()} or set(BUILDERS)
    args.out.mkdir(parents=True, exist_ok=True)

    manifest: dict = {
        "generated": datetime.now(UTC).isoformat(),
        "model_expected": MODEL_EXPECTED,
        "build_tag": "nexus_rag_build",
        "sources": {},
    }
    total = 0
    for name, (filename, builder, registry_rel) in BUILDERS.items():
        if name not in only:
            continue
        docs = builder()
        out_path = args.out / filename
        with out_path.open("w", encoding="utf-8") as fh:
            for doc in docs:
                fh.write(json.dumps(doc, ensure_ascii=False) + "\n")
        registry_path = data_dir / registry_rel
        manifest["sources"][name] = {
            "file": filename,
            "count": len(docs),
            "registry": registry_rel,
            "registry_sha256_16": _sha256(registry_path) if registry_path.is_file() else "",
        }
        total += len(docs)
        print(f"{name:18} {len(docs):6} docs -> {out_path}")

    (args.out / "_manifest.json").write_text(
        json.dumps(manifest, indent=2), encoding="utf-8"
    )
    print(f"total: {total} docs | manifest: {args.out / '_manifest.json'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
