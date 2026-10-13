"""D116 (2026-10-13): a USN journal row's parent directory, joined to the MFT of the same run.

These tests read the case's own run, which is evidence and is never committed. They skip in a clean checkout. On the
run of 2026-10-13 the join must resolve the rows the measurement did: 297,365 of 365,943.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from nexus.langgraph.case_index import _index_header, _open_text_auto, iter_indexable_rows
from nexus.langgraph.event_categories import OTHER, family_category
from nexus.langgraph.mft_join import PARENT_SOURCE, mft_parent_paths, resolve_usn_row, usn_mft_csv

CASE_RUN = (
    Path(__file__).resolve().parents[1] / "cases" / "CASE-C5B04D31" / "runs"
    / "RUN-20261011T110426201672Z-tools-5618aeb2" / "extractions"
)
USN = CASE_RUN / "mftecmd-usn" / "usn.csv"

pytestmark = pytest.mark.skipif(not USN.is_file(), reason="the case run is not present in this checkout")


def test_the_mft_of_the_same_run_is_the_one_joined():
    assert usn_mft_csv(USN) == CASE_RUN / "mftecmd" / "mft.csv"
    assert usn_mft_csv(CASE_RUN / "mftecmd" / "mft.csv") is None  # only the USN file is joined


def test_the_join_resolves_the_measured_share_of_usn_rows():
    header = _index_header(USN)
    resolved = total = 0
    with _open_text_auto(USN) as fh:
        for _n, _raw, fields in iter_indexable_rows(USN, fh, header, file_label=USN.name):
            total += 1
            if resolve_usn_row(USN, fields).get("ParentPath"):
                resolved += 1
    assert total == 365943
    assert resolved == 297365


def test_an_unresolved_row_names_no_path_and_is_not_classified(tmp_path: Path):
    # A USN row whose parent is not in the MFT keeps only its bare name. The name must not become a file path.
    from nexus.langgraph.ecs_normalize import normalize
    from nexus.langgraph.path_sanitize import machine_roots, sanitize_field_map

    paths = mft_parent_paths(str(CASE_RUN / "mftecmd" / "mft.csv"))
    header = _index_header(USN)
    with _open_text_auto(USN) as fh:
        for _n, _raw, fields in iter_indexable_rows(USN, fh, header, file_label=USN.name):
            key = (fields["ParentEntryNumber"], fields["ParentSequenceNumber"])
            if key not in paths:
                resolved = resolve_usn_row(USN, fields)
                assert "ParentPath" not in resolved and "FileName" not in resolved
                ecs = normalize("mftecmd", sanitize_field_map(resolved, tmp_path, roots=machine_roots(tmp_path),
                                                              family="mftecmd"), None)
                assert "path" not in ecs.get("file", {})
                assert family_category("mftecmd/mftecmd-usn/usn.csv", {}) == OTHER
                return
    pytest.skip("every USN row resolves in this run")


def test_a_resolved_row_takes_its_parent_from_the_mft_entry_it_names():
    header = _index_header(USN)
    paths = mft_parent_paths(str(CASE_RUN / "mftecmd" / "mft.csv"))
    with _open_text_auto(USN) as fh:
        for _n, _raw, fields in iter_indexable_rows(USN, fh, header, file_label=USN.name):
            key = (fields["ParentEntryNumber"], fields["ParentSequenceNumber"])
            if key in paths:
                resolved = resolve_usn_row(USN, fields)
                assert resolved["ParentPath"] == paths[key]
                assert resolved["ParentPathSource"] == PARENT_SOURCE
                # The path the row takes is the directory, and the rule then needs the file path it makes with Name.
                assert family_category("mftecmd/mftecmd-usn/usn.csv", {"file_path": resolved["ParentPath"]}) == "file_event"
                assert family_category("mftecmd/mftecmd-usn/usn.csv", {}) == OTHER
                return
    pytest.fail("no resolvable USN row in the run")
