"""Generic catch-all importers (JSONL, CSV).

These are the lowest-priority importers — they handle plain JSONL and CSV
files that no specific importer recognized. The output is a best-effort
mapping with most fields populated from the raw record.
"""
