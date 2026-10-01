/**
 * Ingest — the post-N1–N8 stage, migrated to the kit (WO-U8a).
 *
 * Two paths on one page:
 *   1. Importers — logs/artifacts (Zeek, Suricata, SIEM, cloud, PCAP, …) onto
 *      the same case index via the auto-detect importer registry.
 *   2. SIFT outputs (Option B) — the examiner ran SIFT elsewhere; the outputs
 *      are staged where the indexer and field mappings pick them up. No SIFT
 *      host or MCP required.
 *
 * Kit: PageHeader + Panel + Field/Input/Button, styles in a CSS module, zero
 * inline style objects.
 *
 * One behaviour kept deliberately: both endpoints answer HTTP 200 with an
 * `ok: false` body rather than failing, so the old code checked `r.ok` and
 * surfaced `r.error`. The mutations keep that check — treating a 200 with
 * `ok: false` as success would report an ingest that never happened.
 */
import { useState } from "react";

import { useCase } from "../context/CaseContext";
import { api } from "../api/client";
import { Button, Field, Input, PageHeader, Panel } from "@/ui";
import styles from "./Ingest.module.css";

export default function Ingest() {
  const { activeCase } = useCase();
  const [impPath, setImpPath] = useState("");
  const [impSource, setImpSource] = useState("");
  const [impBusy, setImpBusy] = useState(false);
  const [impResult, setImpResult] = useState("");
  const [siftPath, setSiftPath] = useState("");
  const [siftFamily, setSiftFamily] = useState("");
  const [siftBusy, setSiftBusy] = useState(false);
  const [siftResult, setSiftResult] = useState("");
  const [error, setError] = useState("");

  const runImporter = async () => {
    if (!impPath.trim()) return;
    setImpBusy(true);
    setError("");
    setImpResult("");
    try {
      const response = await api.ingest(
        impPath.trim(),
        impSource.trim() || undefined,
        activeCase,
      );
      if (response.ok) {
        const detail = response.result ? JSON.stringify(response.result) : "";
        setImpResult(
          `Ingested.${detail ? ` ${detail.slice(0, 400)}` : ""}\n${(response.index || []).join("\n")}`,
        );
      } else {
        setError(response.error || "ingest failed");
      }
    } catch (exc) {
      setError((exc as Error).message);
    } finally {
      setImpBusy(false);
    }
  };

  const runSiftIngest = async () => {
    if (!siftPath.trim()) return;
    setSiftBusy(true);
    setError("");
    setSiftResult("");
    try {
      const response = await api.siftIngest(
        siftPath.trim(),
        siftFamily.trim() || undefined,
        activeCase,
      );
      if (response.ok) {
        setSiftResult(
          `Staged: ${(response.staged || []).join(", ")}\n${(response.index || []).join("\n")}`,
        );
      } else {
        setError(response.error || "SIFT ingest failed");
      }
    } catch (exc) {
      setError((exc as Error).message);
    } finally {
      setSiftBusy(false);
    }
  };

  return (
    <div className={styles.page}>
      <PageHeader
        title="Ingest"
        subtitle="Bring later-arriving evidence onto the same case index. Ingested rows join the normal N4–N8 surfaces (Explore, Briefing, Modes) after the index refresh."
        stageCode="N2"
      />

      {error ? (
        <div role="alert" className="error-banner">
          {error}
        </div>
      ) : null}

      <Panel title="Importers — logs & artifacts">
        <p className={styles.hint}>
          Auto-detect and import Zeek/Suricata/SIEM exports, cloud logs, PCAP
          (flow projection), mailboxes and more. Leave “source” empty to let the
          sniffer decide.
        </p>
        <div className={styles.pathRow}>
          <Field label="Path">
            {({ id }) => (
              <Input
                id={id}
                placeholder="Path to file or directory (e.g. D:\evidence\conn.log)"
                value={impPath}
                disabled={impBusy}
                onChange={(event) => setImpPath(event.target.value)}
              />
            )}
          </Field>
          <Field label="Source (optional)">
            {({ id }) => (
              <Input
                id={id}
                placeholder="source"
                value={impSource}
                disabled={impBusy}
                onChange={(event) => setImpSource(event.target.value)}
              />
            )}
          </Field>
          <Button
            variant="primary"
            onClick={runImporter}
            disabled={impBusy || !impPath.trim()}
            data-testid="ingest-run"
          >
            {impBusy ? "Ingesting…" : "Ingest"}
          </Button>
        </div>
        {impResult ? (
          <pre className={styles.output} data-testid="ingest-result">
            {impResult}
          </pre>
        ) : null}
      </Panel>

      <Panel title="SIFT outputs — Option B (no SIFT host required)">
        <p className={styles.hint}>
          Ran SIFT yourself (plaso, vol3, SleuthKit, bulk_extractor)? Stage the
          outputs here as a file, directory, or .zip. Name the family (
          <code>plaso</code>, <code>vol</code>, <code>fls</code>,{" "}
          <code>bulk_extractor</code>) so the field mappings apply — or leave it
          empty to use the file/folder name.
        </p>
        <div className={styles.pathRow}>
          <Field label="Path">
            {({ id }) => (
              <Input
                id={id}
                placeholder="Path to SIFT output (file / dir / .zip)"
                value={siftPath}
                disabled={siftBusy}
                onChange={(event) => setSiftPath(event.target.value)}
              />
            )}
          </Field>
          <Field label="Family (optional)">
            {({ id }) => (
              <Input
                id={id}
                placeholder="family"
                value={siftFamily}
                disabled={siftBusy}
                onChange={(event) => setSiftFamily(event.target.value)}
              />
            )}
          </Field>
          <Button
            variant="primary"
            onClick={runSiftIngest}
            disabled={siftBusy || !siftPath.trim()}
            data-testid="sift-ingest-run"
          >
            {siftBusy ? "Staging…" : "Stage & index"}
          </Button>
        </div>
        {siftResult ? (
          <pre className={styles.output} data-testid="sift-ingest-result">
            {siftResult}
          </pre>
        ) : null}
      </Panel>
    </div>
  );
}
