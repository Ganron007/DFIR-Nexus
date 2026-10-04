#!/usr/bin/env python3
"""WO-KL3 (design time) - quick review of the RAG delta `ir_knowledge_extra`.

Answers the three questions the WO asks, with numbers:

1. **Was it built properly?** model and distance parity with the vendor bundle,
   per-document provenance (source, version, technique ids, an id or url), empty
   and duplicate documents, chunk lengths, and the KL1 case-name guard.
2. **Is it better?** ~20 questions the delta should answer, scored hit@5 with and
   without it.
3. **Do the two disagree?** Where the vendor's older ATT&CK text and the delta's
   v19 text cover the same technique, which one ranks first.

Design time only: this lives under ``devtools/`` and is never imported by
``src/nexus``. It is read-only against the local Chroma store.

Usage::

    python devtools/knowledge/review_rag_delta.py [--out devtools/knowledge/rag-delta-review.json]
"""
from __future__ import annotations

import argparse
import collections
import hashlib
import json
import os
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))

VENDOR = "ir_knowledge"
DELTA = "ir_knowledge_extra"
#: The development set the operator named (§3Z). The delta predates it, but the
#: guard is the acceptance criterion, so it is checked rather than assumed.
CASE_TOKENS = ("base-rd-01", "rd-01", "rd01", "stark research", "srladmin", "wacsvc", "tdungan", "rsydow")

#: Questions the delta should answer, with the id the answer must be and the class
#: marker the retrieved document must also carry. Every id is one the collection
#: actually holds (read from the store, not invented).
#:
#: The marker matters for fairness: the vendor bundle also mentions `T1003` in its
#: ATT&CK text, so expecting the bare id would let a technique description count as
#: a *detection strategy* hit. The question asks whether the delta's own content is
#: retrievable, so the document must be of the right class **and** carry the id.
QUESTIONS: list[tuple[str, str, str, str]] = [
    ("detection strategy for OS credential dumping", "T1003", "attack_detections", "detection strategy"),
    ("detection of process injection via remote thread", "T1055", "attack_detections", "detection strategy"),
    ("detection strategy for scheduled task persistence", "T1053", "attack_detections", "detection strategy"),
    ("detection of PowerShell script block abuse", "T1059.001", "attack_detections", "detection strategy"),
    ("detection of account discovery enumeration", "T1087", "attack_detections", "detection strategy"),
    ("detection of registry run key persistence", "T1547.001", "attack_detections", "detection strategy"),
    ("detection of lateral movement over SMB admin shares", "T1021.002", "attack_detections", "detection strategy"),
    ("detection of kerberoasting", "T1558.003", "attack_detections", "detection strategy"),
    ("detection of LSASS memory access", "T1003.001", "attack_detections", "detection strategy"),
    ("detection of WMI execution", "T1047", "attack_detections", "detection strategy"),
    ("ATLAS technique for search open technical databases", "AML.T0000", "mitre_atlas_techniques", "atlas"),
    ("ATLAS technique for obtaining capabilities", "AML.T0016", "mitre_atlas_techniques", "atlas"),
    ("ATLAS mitigation for limiting model artifact release", "AML.M0001", "mitre_atlas_mitigations", "atlas"),
    ("mitigation for passive AI output obfuscation", "AML.M0002", "mitre_atlas_mitigations", "atlas"),
    ("MBC behaviour for debugger detection", "B0001", "mbc_capa", "mbc"),
    ("MBC behaviour for debugger evasion", "B0002", "mbc_capa", "mbc"),
    ("MBC behaviour for dynamic analysis evasion", "B0003", "mbc_capa", "mbc"),
    ("insider threat matrix section for coercion", "MT012", "itm", "insider threat"),
    ("insider threat matrix boundary testing", "MT022", "itm", "insider threat"),
    ("insider threat emotional vulnerability", "MT012.004", "itm", "insider threat"),
]


def _embedder():
    from sentence_transformers import SentenceTransformer

    os.environ.setdefault("HF_HUB_OFFLINE", "1")
    return SentenceTransformer("BAAI/bge-base-en-v1.5", device="cpu")


def _hit(metas: list[dict], docs: list[str], want: str, marker: str = "") -> bool:
    """Whether a result carries `want`, and `marker` when one is required."""
    low = want.lower()
    for m, d in zip(metas, docs, strict=False):
        blob = json.dumps(m, default=str).lower() + " " + str(d).lower()
        if low in blob and (not marker or marker in blob):
            return True
    return False


def build_check(client) -> dict:
    col = client.get_collection(DELTA)
    vendor = client.get_collection(VENDOR)
    g = col.get(include=["documents", "metadatas"])
    docs, metas = g["documents"], g["metadatas"]
    lengths = [len(str(d)) for d in docs]

    hashes = collections.Counter(hashlib.sha256(str(d).encode("utf-8")).hexdigest() for d in docs)
    dups = sum(c - 1 for c in hashes.values() if c > 1)

    def present(keys: list[str]) -> int:
        return sum(1 for m in metas if any(str(m.get(k) or "").strip() for k in keys))

    contaminated: list[str] = []
    for i, d in enumerate(docs):
        blob = str(d).lower()
        for tok in CASE_TOKENS:
            if tok in blob:
                contaminated.append(f"doc {i} contains {tok!r}")

    empty = sum(1 for d in docs if not str(d).strip())
    short = sum(1 for n in lengths if n < 80)

    return {
        "vendor_count": vendor.count(),
        "delta_count": col.count(),
        "vendor_space": str((vendor.metadata or {}).get("hnsw:space") or "l2"),
        "delta_space": str((col.metadata or {}).get("hnsw:space") or "l2"),
        "by_source": dict(collections.Counter(str(m.get("source")) for m in metas)),
        "provenance": {
            "has_source": present(["source"]),
            "has_version_or_build": present(["built_at", "version", "bundle_tag"]),
            "has_technique_id": present(["technique_id", "atlas_id", "mitre_techniques"]),
            "has_id_or_url": present(["atlas_id", "detection_id", "technique_id", "url", "source_url"]),
            "total": len(metas),
        },
        "empty_docs": empty,
        "duplicate_docs": dups,
        "short_docs_under_80_chars": short,
        "doc_len_min": min(lengths) if lengths else 0,
        "doc_len_median": sorted(lengths)[len(lengths) // 2] if lengths else 0,
        "doc_len_max": max(lengths) if lengths else 0,
        "case_contamination": contaminated[:10],
        "case_contamination_count": len(contaminated),
    }


def retrieval_check(client, model) -> dict:
    vendor = client.get_collection(VENDOR)
    delta = client.get_collection(DELTA)

    rows = []
    vendor_hits = merged_hits = 0
    for question, want, source, marker in QUESTIONS:
        emb = model.encode([question], normalize_embeddings=True).tolist()

        v = vendor.query(query_embeddings=emb, n_results=5,
                         include=["documents", "metadatas", "distances"])
        v_ok = _hit(v["metadatas"][0], v["documents"][0], want, marker)

        # With the delta: the union of both collections, ranked by distance. The
        # product opens the delta as a second collection, so a merged ranking is
        # what "with the delta" means.
        d = delta.query(query_embeddings=emb, n_results=5,
                        include=["documents", "metadatas", "distances"])
        pool = [
            (dist, meta, doc)
            for dist, meta, doc in zip(v["distances"][0] + d["distances"][0],
                                       v["metadatas"][0] + d["metadatas"][0],
                                       v["documents"][0] + d["documents"][0],
                                       strict=True)
        ]
        pool.sort(key=lambda r: r[0])
        top = pool[:5]
        m_ok = _hit([r[1] for r in top], [r[2] for r in top], want, marker)

        vendor_hits += v_ok
        merged_hits += m_ok
        rows.append({
            "question": question, "expects": want, "source": source,
            "vendor_top5": v_ok, "with_delta_top5": m_ok,
            "rank_with_delta": next((i + 1 for i, r in enumerate(pool)
                                     if _hit([r[1]], [r[2]], want, marker)), None),
        })

    n = len(QUESTIONS)
    return {
        "questions": n,
        "vendor_hit_at_5": vendor_hits,
        "with_delta_hit_at_5": merged_hits,
        "vendor_rate": round(vendor_hits / n, 3),
        "with_delta_rate": round(merged_hits / n, 3),
        "rows": rows,
    }


def conflict_check(client, model) -> dict:
    """Where both bundles cover one technique, which ranks first.

    For each technique, find the best document in each bundle that actually
    mentions it, then rank the two against each other for a neutral query. The
    vendor bundle is the older ATT&CK text; the delta is v19. The point is not
    only which is nearer, but which one an examiner would read first for the same
    technique.
    """
    vendor = client.get_collection(VENDOR)
    delta = client.get_collection(DELTA)
    pairs = (
        ("T1003", "OS Credential Dumping"),
        ("T1055", "Process Injection"),
        ("T1059.001", "PowerShell"),
        ("T1547.001", "Registry Run Keys"),
        ("T1021.002", "SMB Admin Shares"),
    )

    def best(res, technique: str):
        for i, (m, doc, dist) in enumerate(zip(res["metadatas"][0], res["documents"][0],
                                               res["distances"][0], strict=True)):
            blob = json.dumps(m, default=str).lower() + " " + str(doc).lower()
            if technique.lower() in blob:
                return i + 1, float(dist), str(m.get("source") or "")
        return None, None, ""

    out = []
    for technique, name in pairs:
        emb = model.encode([f"{name} {technique}"], normalize_embeddings=True).tolist()
        v = vendor.query(query_embeddings=emb, n_results=10,
                         include=["documents", "metadatas", "distances"])
        d = delta.query(query_embeddings=emb, n_results=10,
                        include=["documents", "metadatas", "distances"])
        v_rank, v_dist, v_src = best(v, technique)
        d_rank, d_dist, d_src = best(d, technique)
        # Two different questions, kept separate because they answer differently:
        #   - how high does each bundle rank a doc that actually covers the
        #     technique, within its own results (in-collection rank)?
        #   - head to head on the same embedding space, which doc is nearer?
        nearer = None
        if v_dist is not None and d_dist is not None:
            nearer = "delta" if d_dist < v_dist else "vendor"
        elif d_dist is not None:
            nearer = "delta"
        elif v_dist is not None:
            nearer = "vendor"
        out.append({
            "technique": technique, "name": name,
            "vendor_rank": v_rank, "vendor_distance": v_dist, "vendor_source": v_src,
            "delta_rank": d_rank, "delta_distance": d_dist, "delta_source": d_src,
            "nearer": nearer,
        })
    return {
        "rows": out,
        "compared": sum(1 for r in out if r["nearer"]),
        "delta_rank_1": sum(1 for r in out if r["delta_rank"] == 1),
        "vendor_rank_1": sum(1 for r in out if r["vendor_rank"] == 1),
        "nearer_delta": sum(1 for r in out if r["nearer"] == "delta"),
        "nearer_vendor": sum(1 for r in out if r["nearer"] == "vendor"),
    }


def version_in_text(preview: int = 300) -> dict:
    """Does a doc name its source release version, or only a build timestamp?

    KL3 asks for a *version* per doc. The metadata carries `built_at` (when we
    built it), which is not the same as the upstream release (ATT&CK v19). Checked
    rather than assumed, because the two are easy to confuse.
    """
    import chromadb

    client = chromadb.PersistentClient(path=os.path.expanduser("~/.nexus/data/rag/chroma"))
    delta = client.get_collection(DELTA)
    g = delta.get(include=["documents", "metadatas"], limit=preview)
    named = 0
    for d in g["documents"]:
        low = str(d).lower()
        if "v19" in low or "attack v" in low or "version" in low:
            named += 1
    sources = collections.Counter(str(m.get("source")) for m in g["metadatas"])
    return {"sampled": len(g["documents"]), "naming_a_version": named,
            "has_built_at": sum(1 for m in g["metadatas"] if m.get("built_at")),
            "sources": dict(sources)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path,
                        default=REPO / "devtools" / "knowledge" / "rag-delta-review.json")
    args = parser.parse_args(argv)

    import chromadb

    path = os.path.expanduser("~/.nexus/data/rag/chroma")
    client = chromadb.PersistentClient(path=path)

    print("1/3 build check")
    build = build_check(client)
    print(f"  vendor {build['vendor_count']} / delta {build['delta_count']} docs")
    print(f"  space: vendor {build['vendor_space']} / delta {build['delta_space']}")
    print(f"  empty {build['empty_docs']}, duplicate {build['duplicate_docs']}, "
          f"median len {build['doc_len_median']}")
    print(f"  case contamination: {build['case_contamination_count']}")

    print("2/3 retrieval")
    model = _embedder()
    retr = retrieval_check(client, model)
    print(f"  hit@5 vendor-only {retr['vendor_hit_at_5']}/{retr['questions']} "
          f"({retr['vendor_rate']:.0%})  with delta {retr['with_delta_hit_at_5']}/{retr['questions']} "
          f"({retr['with_delta_rate']:.0%})")

    print("3/3 conflict")
    conf = conflict_check(client, model)
    print(f"  compared {conf['compared']}: delta rank 1 in {conf['delta_rank_1']}, "
          f"vendor rank 1 in {conf['vendor_rank_1']}; nearer: "
          f"delta {conf['nearer_delta']} / vendor {conf['nearer_vendor']}")
    ver = version_in_text()
    print(f"  version in text: {ver['naming_a_version']}/{ver['sampled']} docs name one")

    report = {"build": build, "retrieval": retr, "conflict": conf, "version": ver}
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    print(f"\nreport: {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
