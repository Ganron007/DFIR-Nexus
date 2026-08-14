"""Tests for P1.9 integration modules: export, VQL, vision, knowledge graph, notifications."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from nexus.case import CaseManager, FindingSeverity
from nexus.integration.case_export import (
    CaseExporter,
    export_to_html,
    export_to_json,
    export_to_markdown,
    export_to_stix,
)
from nexus.integration.export_formats import (
    export_asset_graph_svg,
    export_case_zip,
    export_findings_csv,
    export_investigation_snapshot,
    export_ioc_blocklist,
    export_swimlane_svg,
    export_to_docx,
)
from nexus.integration.knowledge_graph import build_case_knowledge_graph
from nexus.integration.vql_runner import (
    MockVelociraptorClient,
    MonitorConfig,
    VQLQuerySpec,
    VQLResult,
    VQLRunner,
)


@pytest.fixture
def test_db(tmp_path: Path) -> Path:
    return tmp_path / "cases.db"


@pytest.fixture
def mgr(test_db: Path) -> CaseManager:
    manager = CaseManager(test_db, secret_key=b"test")
    yield manager
    manager.close()


@pytest.fixture
def bundle(mgr: CaseManager) -> dict:
    case = mgr.create_case(name="export-test", severity=FindingSeverity.HIGH)
    mgr.add_finding(case.id, "LSASS access", technique_ids=["T1003.001"])
    mgr.add_evidence(case.id, name="ev1", metadata={"host": "mbr01"})
    ok, errors = mgr.verify_audit_chain(case.id)
    return {
        "case": case,
        "findings": mgr.list_findings(case.id),
        "evidence": mgr.list_evidence(case.id),
        "audit_log": mgr.get_audit_log(case.id),
        "audit_verified": ok,
        "audit_errors": errors,
    }


# =============================================================================
# VQL Runner
# =============================================================================


class TestVQLRunner:
    def test_run_once_with_mock(self) -> None:
        config = MonitorConfig(endpoint="http://localhost:8000/")
        runner = VQLRunner(config=config, queries=[
            VQLQuerySpec(name="processes", vql="SELECT * FROM pslist()"),
        ])
        results = runner.run_once()
        assert "processes" in results
        assert len(results["processes"].rows) == 2

    def test_add_query(self) -> None:
        config = MonitorConfig(endpoint="http://localhost:8000/")
        runner = VQLRunner(config=config)
        runner.add_query(VQLQuerySpec(name="test", vql="SELECT 1"))
        runner.add_query(VQLQuerySpec(name="test2", vql="SELECT 2"))
        assert len(runner.queries) == 2

    def test_result_handler_called(self) -> None:
        config = MonitorConfig(endpoint="http://localhost:8000/")
        received: list[VQLResult] = []
        runner = VQLRunner(
            config=config,
            queries=[VQLQuerySpec(name="test", vql="SELECT 1")],
            result_handler=received.append,
        )
        runner.run_once()
        assert len(received) == 1

    def test_result_handler_exception_doesnt_crash(self) -> None:
        def bad_handler(_):
            raise RuntimeError("handler boom")
        config = MonitorConfig(endpoint="http://localhost:8000/")
        runner = VQLRunner(
            config=config,
            queries=[VQLQuerySpec(name="test", vql="SELECT 1")],
            result_handler=bad_handler,
        )
        runner.run_once()
        assert "test" in runner.last_results

    def test_stats(self) -> None:
        config = MonitorConfig(endpoint="http://localhost:8000/")
        runner = VQLRunner(config=config, queries=[VQLQuerySpec(name="q1", vql="SELECT 1")])
        stats = runner.stats()
        assert stats["running"] is False
        assert stats["query_count"] == 1

    def test_mock_client(self) -> None:
        config = MonitorConfig(endpoint="http://localhost:8000/")
        client = MockVelociraptorClient(config)
        result = client.query(VQLQuerySpec(name="test", vql="SELECT 1"))
        assert result.query_name == "test"
        assert len(result.rows) >= 1


# =============================================================================
# Case Export
# =============================================================================


class TestCaseExport:
    def test_export_to_json(self, bundle: dict) -> None:
        content = export_to_json(bundle)
        data = json.loads(content)
        assert data["case"]["name"] == "export-test"
        assert len(data["findings"]) == 1
        assert len(data["evidence"]) == 1
        assert "audit_log" in data
        assert data["audit_verified"] is True

    def test_export_to_markdown(self, bundle: dict) -> None:
        content = export_to_markdown(bundle)
        assert "# Case Report: export-test" in content
        assert "LSASS access" in content
        assert "ev1" in content

    def test_export_to_html(self, bundle: dict) -> None:
        content = export_to_html(bundle)
        assert "<!DOCTYPE html>" in content
        assert "export-test" in content
        assert "LSASS access" in content
        assert "<style>" in content

    def test_export_to_stix(self, bundle: dict) -> None:
        content = export_to_stix(bundle)
        data = json.loads(content)
        assert data["type"] == "bundle"
        assert len(data["objects"]) >= 1

    def test_case_exporter_class(self, mgr: CaseManager, bundle: dict) -> None:
        case_id = bundle["case"].id
        exporter = CaseExporter(mgr)
        content = exporter.export(case_id, "json")
        assert "export-test" in content

    def test_case_exporter_unknown_format(self, mgr: CaseManager) -> None:
        case = mgr.create_case(name="test")
        exporter = CaseExporter(mgr)
        with pytest.raises(ValueError):
            exporter.export(case.id, "unknown")


# =============================================================================
# Extended Export Formats
# =============================================================================


class TestExportFormats:
    def test_export_csv(self, bundle: dict) -> None:
        csv_text = export_findings_csv(bundle["findings"])
        assert "LSASS access" in csv_text

    def test_export_snapshot(self, bundle: dict) -> None:
        snap = export_investigation_snapshot(bundle)
        assert "T1003.001" in snap

    def test_export_swimlane_svg(self, bundle: dict) -> None:
        svg = export_swimlane_svg(bundle)
        assert "<svg" in svg

    def test_export_asset_graph_svg(self, bundle: dict) -> None:
        graph = export_asset_graph_svg(bundle)
        assert "mbr01" in graph

    def test_export_case_zip(self, bundle: dict) -> None:
        zbytes = export_case_zip(bundle)
        assert zbytes[:2] == b"PK"

    def test_export_to_docx(self, bundle: dict) -> None:
        docx = export_to_docx(bundle)
        assert len(docx) > 100
        assert docx[:2] == b"PK"

    def test_ioc_blocklist(self, bundle: dict) -> None:
        text = export_ioc_blocklist(bundle)
        assert "T1003.001" in text


# =============================================================================
# Knowledge Graph
# =============================================================================


class TestKnowledgeGraph:
    def test_build_knowledge_graph(self, bundle: dict) -> None:
        kg = build_case_knowledge_graph(bundle)
        data = kg.to_dict()
        assert any(e["kind"] == "finding" for e in data["entities"])
        assert any(e["kind"] == "evidence" for e in data["entities"])
        assert data["relations"]


# =============================================================================
# Vision
