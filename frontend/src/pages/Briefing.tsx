/**
 * Briefing — WP 4i.4. The examiner's first view of a processed case.
 *
 * What was collected (inventory + parser ledger), what the signatures already
 * caught (alert surface), where the signal density is (playbook auto-scan),
 * top entities, hosts, time range, and the intake echo. Deterministic — no
 * LLM required. Clicking a needle drops into Explore with that needle set.
 */
import { useEffect, useRef, useState } from "react";
import { useNavigate, Link } from "react-router-dom";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import { api, type BriefingDirection, type BriefingResponse, type CaseDigestResponse, type InterpretRoundsResponse, type Mode1FullRunResponse } from "../api/client";
import { useCase } from "../context/CaseContext";

export default function Briefing() {
  const { activeCase, refreshStages, mode } = useCase();
  const navigate = useNavigate();
  const [brief, setBrief] = useState<BriefingResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  // Mode 2/3 pipeline run (question-driven) + live stage feed
  const [modeQuestion, setModeQuestion] = useState("");
  const [modeRunId, setModeRunId] = useState("");
  const [modeRunStatus, setModeRunStatus] = useState("");
  const [modeStages, setModeStages] = useState<
    { stage?: string; tool?: string; host?: string; status?: string; detail?: string }[]
  >([]);
  const [modeRunError, setModeRunError] = useState("");
  const modeRunPollRef = useRef<ReturnType<typeof setInterval> | null>(null);
  // Lazy LLM layer — loaded after the deterministic briefing renders so a
  // slow local model never blocks the page (was an inline route call).
  const [directions, setDirections] = useState<BriefingDirection[] | null>(null);

  // GATE-A — deterministic Case Digest (fetched for Mode 2/3 only).
  const [digest, setDigest] = useState<CaseDigestResponse | null>(null);
  const [digestError, setDigestError] = useState("");
  // GATE-B — interpret round log (Mode 2/3 only).
  const [rounds, setRounds] = useState<InterpretRoundsResponse | null>(null);
  // Mode 2 run options — decided BEFORE the run.
  const [interpretRounds, setInterpretRounds] = useState(3);
  const [contextWindow, setContextWindow] = useState(1_000_000);
  // WP 4j.1: alert rows expand to show interpretation (meaning + what to check)
  const [openAlert, setOpenAlert] = useState<number | null>(null);
  // WP 4j.3: guided first-pass step completion (per-case, local)
  const [doneSteps, setDoneSteps] = useState<Record<string, boolean>>({});
  // WP 4j.5d: Mode 1 full run — tracked server-side run; survives navigation
  const [fullRunResult, setFullRunResult] = useState<Mode1FullRunResponse | null>(null);
  const [fullRunError, setFullRunError] = useState("");
  const [reprocess, setReprocess] = useState(false);
  const fullRunPollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const stopFullRunPoll = () => {
    if (fullRunPollRef.current) {
      clearInterval(fullRunPollRef.current);
      fullRunPollRef.current = null;
    }
  };

  const pollFullRun = () => {
    stopFullRunPoll();
    fullRunPollRef.current = setInterval(async () => {
      try {
        const r = await api.mode1FullRunStatus();
        setFullRunResult(r);
        if (r.status !== "running") {
          stopFullRunPoll();
          if (activeCase) refreshStages(activeCase);
        }
      } catch {
        /* transient poll failure — keep polling */
      }
    }, 1500);
  };

  // On mount / case switch: reconnect to an in-flight or finished run.
  useEffect(() => {
    if (!activeCase) return;
    let stale = false;
    api.mode1FullRunStatus()
      .then((r) => {
        if (stale || r.status === "never_run") return;
        setFullRunResult(r);
        if (r.status === "running") pollFullRun();
      })
      .catch(() => { /* no record yet — fine */ });
    return () => {
      stale = true;
      stopFullRunPoll();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeCase]);

  const fullRunRunning = fullRunResult?.status === "running";
  // A prior terminal run exists → the button is a re-run; the reprocess
  // checkbox lets the examiner supersede open DRAFTs and re-stage fresh.
  const hasPriorRun = !!fullRunResult && !fullRunRunning && fullRunResult.status !== "never_run";

  const fullRun = async () => {
    setFullRunError("");
    // Optimistic state — the POST returns instantly now, but show the running
    // card the moment the click lands so there's never a dead-looking gap.
    setFullRunResult({
      status: "running",
      stage: "starting",
      needles_done: 0,
      needles_total: 0,
      needles_scanned: 0,
      bookmarks_added: 0,
      drafts: [],
      skipped: [],
    });
    try {
      const r = await api.mode1FullRun({ reprocess });
      setFullRunResult(r);
      if (r.status === "running") pollFullRun();
    } catch (e) {
      // 409 = a run is already live — attach to it instead of failing
      const rec = (e as { detail?: Mode1FullRunResponse }).detail;
      if ((e as { status?: number }).status === 409 && rec) {
        setFullRunResult(rec);
        if (rec.status === "running") pollFullRun();
      } else {
        setFullRunError((e as Error).message);
      }
    }
  };

  useEffect(() => {
    if (!activeCase) return;
    try {
      const raw = localStorage.getItem(`nexus.walkthrough.${activeCase}`);
      setDoneSteps(raw ? JSON.parse(raw) : {});
    } catch {
      setDoneSteps({});
    }
  }, [activeCase]);

  // Mode 2/3: question-driven pipeline run with a live stage feed.
  const stopModeRunPoll = () => {
    if (modeRunPollRef.current) {
      clearInterval(modeRunPollRef.current);
      modeRunPollRef.current = null;
    }
  };

  const pollModeRun = (runId: string) => {
    stopModeRunPoll();
    modeRunPollRef.current = setInterval(async () => {
      try {
        const s = await api.pipelineStatus(runId);
        setModeRunStatus(s.status);
        setModeStages(s.stages || []);
        if (s.status === "complete" || s.status === "error") {
          stopModeRunPoll();
          if (s.error) setModeRunError(s.error);
          // Pull the fresh briefing (interpretation/verdict may be written)
          api.caseBriefing().then(setBrief).catch(() => undefined);
          api.caseDigest().then((d) => { if (!d.error) setDigest(d); }).catch(() => undefined);
          api.caseRounds().then((r) => { if (r.summary) setRounds(r); }).catch(() => undefined);
          refreshStages(activeCase);
        }
      } catch (e) {
        stopModeRunPoll();
        setModeRunError((e as Error).message);
      }
    }, 3000);
  };

  useEffect(() => () => stopModeRunPoll(), []);

  // GATE-A — digest loads for Mode 2/3 (Mode 1 has directions instead).
  // GATE-B — rounds load alongside it after a run.
  useEffect(() => {
    setDigest(null);
    setDigestError("");
    setRounds(null);
    if (!activeCase || (mode !== "2" && mode !== "3")) return;
    let stale = false;
    api.caseDigest()
      .then((d) => {
        if (stale) return;
        if (d.error) setDigestError(d.error);
        else setDigest(d);
      })
      .catch((e) => { if (!stale) setDigestError((e as Error).message); });
    api.caseRounds()
      .then((r) => { if (!stale && r.summary) setRounds(r); })
      .catch(() => undefined);
    return () => { stale = true; };
  }, [activeCase, mode]);

  const runModePipeline = async () => {
    if (!activeCase) return;
    setModeRunError("");
    setModeStages([]);
    setModeRunStatus("running");
    try {
      const r = await api.pipelineRun({
        mode: "coverage",
        case_id: activeCase,
        question: modeQuestion.trim(),
        interpret_rounds: interpretRounds,
        context_window: contextWindow,
      });
      setModeRunId(r.run_id);
      pollModeRun(r.run_id);
    } catch (e) {
      setModeRunStatus("error");
      setModeRunError((e as Error).message);
    }
  };

  const toggleStep = (key: string) => {
    setDoneSteps((prev) => {
      const next = { ...prev, [key]: !prev[key] };
      try {
        localStorage.setItem(`nexus.walkthrough.${activeCase}`, JSON.stringify(next));
      } catch {
        /* localStorage unavailable — keep in-memory state */
      }
      return next;
    });
  };

  // WP 4j.13 UX: briefing cache per case — revisiting doesn't rebuild from
  // scratch. The cache is invalidated on case switch or explicit refresh.
  const briefingCacheRef = useRef<Record<string, { data: BriefingResponse; ts: number }>>({});
  const BRIEFING_CACHE_TTL = 60_000; // 60 s

  useEffect(() => {
    setLoading(true);
    setError("");
    setDirections(null);
    let stale = false;
    const cacheKey = activeCase;
    const cached = briefingCacheRef.current[cacheKey];
    if (cached && (Date.now() - cached.ts) < BRIEFING_CACHE_TTL) {
      setBrief(cached.data);
      setLoading(false);
      // Directions are a Mode 1 layer only (Mode 2/3 have the digest + LLM run).
      if (mode === "1") {
        api.caseBriefingDirections()
          .then((d) => { if (!stale) setDirections(d.directions || []); })
          .catch(() => { if (!stale) setDirections([]); });
      }
      return () => { stale = true; };
    }
    api.caseBriefing()
      .then((b) => {
        if (stale) return;
        setBrief(b);
        briefingCacheRef.current[cacheKey] = { data: b, ts: Date.now() };
        setLoading(false);
        // Lazy LLM layer — Mode 1 only.
        if (mode === "1") {
          api.caseBriefingDirections()
            .then((d) => { if (!stale) setDirections(d.directions || []); })
            .catch(() => { if (!stale) setDirections([]); });
        }
      })
      .catch((e) => { if (!stale) { setError((e as Error).message); setLoading(false); } });
    return () => { stale = true; };
  }, [activeCase, mode]);

  const searchNeedle = (needle: string, family?: string) => {
    const params = new URLSearchParams({ needles: needle });
    if (family) params.set("family", family);
    navigate(`/explore?${params}`);
  };

  if (loading) return <div className="loading">Building briefing…</div>;
  if (error) return <div className="error-banner">{error}</div>;
  if (!brief) return null;

  const scanStats = brief.scan_stats || {};
  const truncReasons = scanStats.truncated_reasons || [];
  const ledger = brief.ledger || { entries: [], ok: 0, skip: 0, fail: 0 };
  const inv = brief.inventory || {};
  const scan = brief.needle_scan || [];
  const signalScan = scan.filter((s) => !s.ubiquitous);
  const backgroundTerms = scan.filter((s) => s.ubiquitous);
  const itmCoverage = brief.itm_coverage || [];
  const facts = brief.needle_facts || [];
  const alerts = brief.alerts || [];
  const entities = brief.entities || {};
  const intake = brief.intake || {};
  const walkthrough = brief.walkthrough || [];

  return (
    <div>
      <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 4, flexWrap: "wrap" }}>
        <h2 style={{ marginBottom: 0 }}>Case Briefing</h2>
        {mode === "1" && (
        <button
          className="btn btn-sm"
          style={{ marginLeft: "auto", fontWeight: 600 }}
          disabled={fullRunRunning || scan.length === 0}
          title={
            fullRunRunning
              ? "A Mode 1 full run is already in progress — status below"
              : scan.length === 0
                ? "No playbook needles matched any evidence — nothing to promote"
                : `Needle scan: bookmark hits and stage one DRAFT per needle. This does not call the LLM. The interpretation card below does.`
          }
          onClick={fullRun}
        >
          {fullRunRunning ? "Needle scan in progress…" : hasPriorRun ? "↻ Re-run needle scan" : "▶ Needle scan"}
        </button>
        )}
        {mode === "1" && hasPriorRun && !fullRunRunning && (
          <label style={{ fontSize: 12, color: "var(--text-muted)", display: "flex", alignItems: "center", gap: 4 }}
            title="Supersede open DRAFT findings for hit needles and stage fresh ones. APPROVED findings stay signed — a fresh DRAFT revision is staged alongside them for comparison and approval.">
            <input type="checkbox" checked={reprocess} onChange={(e) => setReprocess(e.target.checked)} />
            reprocess (refresh drafts / revise approved)
          </label>
        )}
      </div>
      <p style={{ fontSize: 12, color: "var(--text-muted)", marginBottom: 16 }}>
        Auto-generated after processing — what was collected, what the signatures
        already caught, and where to start digging.
      </p>

      {/* Mode 1 (LLM) — question-driven interpretation run with the live feed */}
      {mode === "1" && (
        <div className="card" style={{ borderLeft: "3px solid var(--purple)" }}>
          <div className="card-title" style={{ marginBottom: 6 }}>
            Mode 1 — LLM interpretation run (coverage)
          </div>
          <div style={{ fontSize: 12, color: "var(--text-muted)", marginBottom: 8 }}>
            The deterministic lane parses and indexes, then the LLM interprets every entity
            against RAG methodology and threat intel, and stages DRAFT findings for your approval.
          </div>
          <textarea
            value={modeQuestion}
            onChange={(e) => setModeQuestion(e.target.value)}
            placeholder="Examiner question for the interpretation (e.g. 'What did D:\\m.exe do and is it malicious?') — drives the LLM analysis"
            rows={2}
            style={{ width: "100%", marginBottom: 8, fontSize: 12 }}
            disabled={modeRunStatus === "running"}
          />
          <div style={{ display: "flex", gap: 12, alignItems: "center", marginBottom: 8, flexWrap: "wrap" }}>
            <label style={{ fontSize: 11, color: "var(--text-muted)", display: "flex", alignItems: "center", gap: 4 }}
              title="Interpretation rounds: how many orient → verify → reconcile passes the LLM loop runs (1–5).">
              rounds
              <input
                type="number" min={1} max={5} value={interpretRounds}
                onChange={(e) => setInterpretRounds(Math.max(1, Math.min(5, Number(e.target.value) || 3)))}
                disabled={modeRunStatus === "running"}
                style={{ width: 52, fontSize: 11 }}
              />
            </label>
            <label style={{ fontSize: 11, color: "var(--text-muted)", display: "flex", alignItems: "center", gap: 4 }}
              title="Your model's max context window (tokens). The context allocator packs window × 0.7 so interpretation sees as much of the case as the model can hold.">
              context window
              <input
                type="number" min={8000} step={100000} value={contextWindow}
                onChange={(e) => setContextWindow(Math.max(8000, Number(e.target.value) || 1_000_000))}
                disabled={modeRunStatus === "running"}
                style={{ width: 110, fontSize: 11 }}
              />
              tokens
            </label>
          </div>
          <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
            <button
              className="btn btn-primary btn-sm"
              onClick={runModePipeline}
              disabled={modeRunStatus === "running" || !activeCase}
            >
              {modeRunStatus === "running"
                ? "Running…"
                : "▶ Run LLM interpretation"}
            </button>
            {modeRunStatus === "complete" && (
              <span style={{ fontSize: 12, color: "var(--ok)" }}>
                Complete — DRAFT findings staged (review in Approve)
              </span>
            )}
            {modeRunError && <span style={{ fontSize: 12, color: "var(--danger)" }}>{modeRunError}</span>}
          </div>
          {modeStages.length > 0 && (
            <div style={{ marginTop: 10, fontSize: 11, fontFamily: "monospace", color: "var(--text-muted)" }}>
              {modeStages.slice(-14).map((s, i) => (
                <div key={i}>
                  <span style={{ color: s.status === "error" ? "var(--danger)" : s.status === "running" ? "var(--accent)" : "var(--text-secondary)" }}>
                    [{s.stage || s.tool || "?"}]
                  </span>{" "}
                  {s.status || ""}{s.detail ? ` — ${s.detail}` : ""}
                </div>
              ))}
            </div>
          )}
          {modeRunId && (
            <div style={{ marginTop: 6, fontSize: 10, color: "var(--text-muted)" }}>
              run {modeRunId}
            </div>
          )}
        </div>
      )}

      {/* Mode 2/3 — the depths run from Agent Run; the lane is the prerequisite */}
      {(mode === "2" || mode === "3") && (
        <div className="card" style={{ borderLeft: "3px solid var(--purple)", marginBottom: 12 }}>
          <div className="card-title" style={{ marginBottom: 6 }}>
            {mode === "2" ? "Mode 2 — Multi-role runs from Agent Run" : "Mode 3 — Multi-agent runs from Agent Run"}
          </div>
          <div style={{ fontSize: 12, color: "var(--text-muted)", marginBottom: 8 }}>
            {mode === "2"
              ? "The deterministic lane is the prerequisite. Start the supervised multi-role run on Agent Run (plan → run → verify → stage); you steer, pause/stop and stage."
              : "The deterministic lane is the prerequisite. Start the concurrent multi-agent team on Agent Run (Investigation Board): simultaneous seats, a shared claim board, disputes and join decisions."}
          </div>
          <button className="btn btn-sm btn-primary" onClick={() => navigate("/agent-run")}>
            Open Agent Run →
          </button>
        </div>
      )}

      {/* GATE-A — deterministic Case Digest: every fact the interpretation must reconcile */}
      {(mode === "1" || mode === "2" || mode === "3") && (
        <div className="card" style={{ borderLeft: "3px solid var(--purple)" }}>
          <div className="card-title" style={{ marginBottom: 6 }}>
            Case Digest{" "}
            <span style={{ fontSize: 10, color: "var(--text-muted)" }}>
              (deterministic — everything the interpretation must reconcile)
            </span>
          </div>
          {digestError && <div style={{ fontSize: 12, color: "var(--danger)" }}>{digestError}</div>}
          {!digest && !digestError && (
            <span style={{ fontSize: 11, color: "var(--text-muted)" }}>Building digest…</span>
          )}
          {digest && (() => {
            const d = digest.digest;
            const digestTruncated = Boolean(d.scan_stats?.truncated);
            const withHits = d.signal_map?.with_hits?.length ?? 0;
            const zeroHits = d.signal_map?.zero_hit?.length ?? 0;
            return (
              <>
                <div style={{ fontSize: 12, color: "var(--text-secondary)", marginBottom: 6 }}>
                  {Math.max(0, (d.signal_map?.scanned ?? 0) - (d.signal_map?.unscanned?.length ?? 0))} needles scanned
                  {d.signal_map?.unscanned?.length ? ` (${d.signal_map.unscanned.length} NOT scanned)` : ""} · {withHits} with hits ·{" "}
                  {zeroHits} checked-absent (negative evidence) · {(d.alerts || []).length} high/critical alert(s) ·{" "}
                  {d.hosts?.length ?? 0} host(s) · {Object.keys(d.inventory || {}).length} famil{Object.keys(d.inventory || {}).length === 1 ? "y" : "ies"} ·{" "}
                  timeline: {d.timeline?.source || "n/a"}
                </div>
                {digestTruncated && (
                  <div style={{ fontSize: 11, color: "var(--warning)", marginBottom: 6 }}>
                    LOWER BOUNDS — the briefing scan was truncated (
                    {(d.scan_stats?.truncated_reasons || []).join("; ") || "cap reached"}).
                    Counts below are minimums.
                  </div>
                )}
                {(d.scope?.explicitly_absent?.length ?? 0) > 0 && (
                  <div style={{ fontSize: 11, color: "var(--warning)", marginBottom: 6 }}>
                    Scope — NOT in evidence (stated as scope, never as “no compromise”):{" "}
                    {d.scope.explicitly_absent.join("; ")}
                  </div>
                )}
                {(d.scope?.evidence_classes_present?.length ?? 0) > 0 && (
                  <div style={{ fontSize: 11, color: "var(--text-muted)", marginBottom: 6 }}>
                    In evidence: {d.scope.evidence_classes_present.join(", ")}
                  </div>
                )}
                {digest.markdown && (
                  <details>
                    <summary style={{ fontSize: 11, cursor: "pointer", color: "var(--accent)" }}>
                      Full digest (what the LLM was given)
                    </summary>
                    <div style={{ marginTop: 8, maxHeight: 420, overflow: "auto" }}>
                      <article className="report-markdown">
                        <ReactMarkdown remarkPlugins={[remarkGfm]}>{digest.markdown}</ReactMarkdown>
                      </article>
                    </div>
                  </details>
                )}
              </>
            );
          })()}
        </div>
      )}

      {/* GATE-B — interpret round log (Mode 2/3): Orient → Verify → Reconcile */}
      {(mode === "2" || mode === "3") && rounds?.summary && (
        <div className="card" style={{ borderLeft: "3px solid var(--purple)" }}>
          <div className="card-title" style={{ marginBottom: 6 }}>
            Interpretation rounds{" "}
            <span style={{ fontSize: 10, color: "var(--text-muted)" }}>
              (Orient → Verify → Reconcile — replay of how the LLM got there)
            </span>
          </div>
          <div style={{ fontSize: 12, color: "var(--text-secondary)", marginBottom: 6 }}>
            {rounds.summary.rounds_run}/{rounds.summary.rounds_requested} verify round(s)
            {" · stop: "}{rounds.summary.stop_reason}
            {" · "}{rounds.summary.hypotheses.length} hypothesis/es
            {" · "}{rounds.summary.notes.length} verification note(s)
            {" · "}{rounds.summary.findings_emitted} finding(s) emitted
            {" · reconciliation "}{rounds.summary.reconciliation.addressed} addressed
            {rounds.summary.reconciliation.unaddressed.length > 0 &&
              ` / ${rounds.summary.reconciliation.unaddressed.length} unaddressed`}
          </div>
          {rounds.summary.hypotheses.length > 0 && (
            <ul style={{ fontSize: 12, margin: "0 0 8px 18px", padding: 0 }}>
              {rounds.summary.hypotheses.map((h) => (
                <li key={h.id}>
                  <b>{h.id}</b>: {h.statement}
                  {h.why ? <span style={{ color: "var(--text-muted)" }}> — {h.why}</span> : null}
                </li>
              ))}
            </ul>
          )}
          {rounds.summary.reconciliation.unaddressed.length > 0 && (
            <div style={{ fontSize: 11, color: "var(--warning)", marginBottom: 8 }}>
              Still unaddressed (verdict must state these as open):{" "}
              {rounds.summary.reconciliation.unaddressed.map((u) => `[${u.kind}] ${u.value}`).join("; ")}
            </div>
          )}
          <details>
            <summary style={{ fontSize: 11, cursor: "pointer", color: "var(--accent)" }}>
              Round detail ({rounds.rounds.length} artifact(s))
            </summary>
            <div style={{ marginTop: 8 }}>
              {rounds.rounds.map((r) => (
                <div key={`${r.round}-${r.kind}`} style={{ marginBottom: 10 }}>
                  <div style={{ fontSize: 12, fontWeight: 600 }}>
                    Round {r.round} — {r.kind}
                  </div>
                  {r.entries && r.entries.length > 0 && (
                    <ul style={{ fontSize: 11, margin: "4px 0 0 18px", padding: 0 }}>
                      {r.entries.map((e, i) => (
                        <li key={i}>
                          <span style={{ fontFamily: "monospace" }}>{e.kind}</span>:{" "}
                          {String((e.params?.dsl as string) || e.params?.value || "")}
                          {e.error ? ` — ERROR: ${e.error}` : ` — ${e.count ?? 0} row(s)`}
                          {e.why ? <span style={{ color: "var(--text-muted)" }}> ({e.why})</span> : null}
                          {e.audit_id ? <span style={{ color: "var(--text-muted)" }}> [{e.audit_id}]</span> : null}
                        </li>
                      ))}
                    </ul>
                  )}
                  {r.notes && r.notes.length > 0 && (
                    <ul style={{ fontSize: 11, margin: "4px 0 0 18px", padding: 0 }}>
                      {r.notes.map((n, i) => (
                        <li key={i}>
                          {n.hypothesis} → <b>{n.status}</b>: {n.evidence}
                        </li>
                      ))}
                    </ul>
                  )}
                </div>
              ))}
            </div>
          </details>
        </div>
      )}

      {/* Mode 2 — LLM interpretation verdict (from analysis/interpretation.md) */}
      {(mode === "2" || mode === "3") && brief.mode_interpretation && (
        <div className="card" style={{ borderLeft: "3px solid var(--purple)" }}>
          <div className="card-title" style={{ marginBottom: 6 }}>Mode 2 Interpretation (LLM)</div>
          <article className="report-markdown">
            <ReactMarkdown remarkPlugins={[remarkGfm]}>{brief.mode_interpretation}</ReactMarkdown>
          </article>
        </div>
      )}
      {(mode === "2" || mode === "3") && !brief.mode_interpretation && (brief.findings_summary?.count ?? 0) > 0 && (
        <div className="card">
          <div className="card-title" style={{ marginBottom: 6 }}>
            Staged findings ({brief.findings_summary?.count} · {brief.findings_summary?.drafts} DRAFT)
          </div>
          <ul style={{ fontSize: 12, margin: "0 0 0 18px", padding: 0 }}>
            {(brief.findings_summary?.top || []).map((f) => (
              <li key={f.id}>
                [{f.severity}/{f.confidence}] {f.title}
              </li>
            ))}
          </ul>
        </div>
      )}
      {(mode === "2" || mode === "3") && !brief.mode_interpretation && brief.ti_context && (
        <div className="card">
          <div className="card-title" style={{ marginBottom: 6 }}>Threat intel (context)</div>
          <article className="report-markdown">
            <ReactMarkdown remarkPlugins={[remarkGfm]}>{brief.ti_context}</ReactMarkdown>
          </article>
        </div>
      )}

      {/* WP 4j.5d — tracked full run: live progress, then per-stage summary */}
      {mode === "1" && fullRunError && <div className="error-banner">{fullRunError}</div>}
      {mode === "1" && fullRunRunning && (
        <div className="card" style={{ borderLeft: "3px solid var(--accent)" }}>
          <div className="card-title" style={{ marginBottom: 6 }}>
            Full run in progress — {fullRunResult?.stage || "starting"}
          </div>
          <div style={{ fontSize: 12, color: "var(--text-muted)", marginBottom: 8 }}>
            Needle {fullRunResult?.needles_done ?? 0}/{fullRunResult?.needles_total ?? 0}
            {fullRunResult?.current && ` — ${fullRunResult.current}`}
            {" · "}{fullRunResult?.drafts.length ?? 0} draft(s) staged
            {" · "}{fullRunResult?.bookmarks_added ?? 0} bookmark(s) added
          </div>
          <div style={{ height: 6, background: "var(--bg-tertiary)", borderRadius: 3, overflow: "hidden" }}>
            <div style={{
              height: "100%",
              width: `${fullRunResult?.needles_total ? Math.round(((fullRunResult.needles_done ?? 0) / fullRunResult.needles_total) * 100) : 0}%`,
              background: "var(--accent)", transition: "width 0.5s",
            }} />
          </div>
        </div>
      )}
      {mode === "1" && fullRunResult && !fullRunRunning && (
        <div className="card" style={{ borderLeft: `3px solid ${fullRunResult.status === "complete" ? "var(--ok)" : "var(--danger)"}` }}>
          <div className="card-title" style={{ marginBottom: 6 }}>
            {fullRunResult.status === "complete"
              ? `Full run complete — ${fullRunResult.drafts_staged ?? fullRunResult.drafts.length} DRAFT finding(s) staged`
              : fullRunResult.status === "interrupted"
                ? "Full run interrupted — server restarted mid-run; safe to re-run"
                : `Full run failed — ${fullRunResult.error || "unknown error"}`}
          </div>
          <div style={{ fontSize: 12, color: "var(--text-muted)", marginBottom: 8 }}>
            {fullRunResult.needles_scanned} needles scanned · {fullRunResult.needles_hit_total ?? fullRunResult.needles_total ?? 0} with hits
            {(fullRunResult.needles_capped ?? 0) > 0 && ` (${fullRunResult.needles_capped} more hit — raise max_needles to include)`}
            {fullRunResult.scan_truncated && " · counts are lower bounds (scan truncated)"}
            {" · "}{fullRunResult.bookmarks_added} bookmark(s) added to Workbench
            {(fullRunResult.superseded?.length ?? 0) > 0 && ` · ${fullRunResult.superseded!.length} draft(s) superseded`}
            {(fullRunResult.revised_approved?.length ?? 0) > 0 && ` · ${fullRunResult.revised_approved!.length} approved signal(s) revised (fresh DRAFT staged)`}
          </div>
          {fullRunResult.drafts.length > 0 && (
            <ul style={{ fontSize: 12, margin: "0 0 8px 18px", padding: 0 }}>
              {fullRunResult.drafts.map((d) => (
                <li key={d.finding_id || d.title}>
                  {d.title}
                  {d.confidence_adjusted?.length ? (
                    <span style={{ color: "var(--warn)", fontSize: 11 }} title={d.confidence_adjusted.join("\n")}>
                      {" "}· confidence capped → LOW (needs corroboration)
                    </span>
                  ) : null}
                </li>
              ))}
            </ul>
          )}
          {fullRunResult.skipped.length > 0 && (
            <div style={{ fontSize: 11, color: "var(--text-muted)", marginBottom: 8 }}>
              Skipped: {fullRunResult.skipped.map((s) => `${s.needle || "?"} (${s.reason})`).join(" · ")}
            </div>
          )}
          <div style={{ fontSize: 12 }}>
            {fullRunResult.next}{" "}
            <button className="btn btn-sm" onClick={() => navigate("/approve")}>
              Review in Approve →
            </button>
          </div>
        </div>
      )}

      {/* WP 4j.3 — guided first pass: the walkthrough an examiner follows (Mode 1) */}
      {mode === "1" && walkthrough.length > 0 && (
        <div className="card" style={{ borderLeft: "3px solid var(--accent)" }}>
          <div className="card-title" style={{ marginBottom: 4 }}>
            Guided First Pass
            <span style={{ fontSize: 10, color: "var(--text-muted)", marginLeft: 8 }}>
              {Object.values(doneSteps).filter(Boolean).length}/{walkthrough.length} steps done
            </span>
          </div>
          <p style={{ fontSize: 12, color: "var(--text-muted)", margin: "0 0 10px" }}>
            Work top-down: triage what the signatures caught, map who/where,
            read the signal clusters, then run the starting points.
          </p>
          {walkthrough.map((st) => {
            const done = !!doneSteps[st.key];
            return (
              <div key={st.key} style={{
                display: "flex", gap: 10, padding: "8px 0",
                borderTop: "1px solid var(--border)", opacity: done ? 0.55 : 1,
              }}>
                <input
                  type="checkbox"
                  checked={done}
                  onChange={() => toggleStep(st.key)}
                  style={{ width: "auto", alignSelf: "flex-start", marginTop: 3, flexShrink: 0, cursor: "pointer" }}
                />
                <div style={{ flex: 1 }}>
                  <div style={{ fontSize: 13, fontWeight: 600 }}>
                    {st.order}. {st.title}
                    <span className="badge" style={{ fontSize: 9, marginLeft: 8 }}>{st.count}</span>
                    {done && <span style={{ fontSize: 10, color: "var(--success)", marginLeft: 8 }}>done</span>}
                  </div>
                  <div style={{ fontSize: 11, color: "var(--text-muted)", margin: "2px 0 6px" }}>{st.why}</div>
                  {st.learn && (st.learn.headline || st.learn.why_matters.length > 0) && (
                    <div style={{
                      fontSize: 11, marginBottom: 6, padding: "6px 8px",
                      background: "var(--bg-tertiary)", borderRadius: 4,
                    }}>
                      {st.learn.headline && (
                        <div style={{ fontWeight: 600, marginBottom: 2 }}>Why this matters: {st.learn.headline}</div>
                      )}
                      {st.learn.why_matters.length > 0 && (
                        <ul style={{ margin: "2px 0 0 16px", padding: 0, color: "var(--text-muted)" }}>
                          {st.learn.why_matters.map((w, wi) => <li key={wi}>{w}</li>)}
                        </ul>
                      )}
                    </div>
                  )}
                  {st.actions.length > 0 && (
                    <div style={{ display: "flex", flexWrap: "wrap", gap: 4 }}>
                      {st.actions.map((a, ai) => (
                        <button
                          key={ai}
                          className="btn btn-sm clickable-tint"
                          style={{ fontFamily: "monospace", fontSize: 10 }}
                          title={a.label}
                          onClick={() => searchNeedle(a.needle, a.family || undefined)}
                        >
                          {a.needle.length > 34 ? a.needle.slice(0, 34) + "…" : a.needle}
                          {typeof a.hits === "number" && a.hits > 0 ? ` (${a.hits})` : ""}
                        </button>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            );
          })}
          <p style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 8, marginBottom: 0 }}>
            When the steps stop being obvious, switch to Steer Chat and ask your
            own questions — you are the driver.
          </p>
        </div>
      )}

      {/* Intake echo — what the examiner said they were looking for */}
      {(intake.question || intake.subjects || intake.hypothesis) && (
        <div className="card" style={{ borderLeft: "3px solid var(--accent)" }}>
          <div className="card-title" style={{ marginBottom: 8 }}>Investigation Focus</div>
          {intake.question && <div style={{ fontSize: 13, marginBottom: 4 }}><strong>Question:</strong> {intake.question}</div>}
          {intake.subjects && <div style={{ fontSize: 13, marginBottom: 4 }}><strong>Subjects:</strong> {intake.subjects}</div>}
          {intake.hypothesis && <div style={{ fontSize: 13 }}><strong>Hypothesis:</strong> {intake.hypothesis}</div>}
        </div>
      )}

      {/* WP 4i.5 — LLM investigation directions grounded in the deterministic numbers (Mode 1) */}
      {mode === "1" && directions === null && (
        <div className="card" style={{ borderLeft: "3px solid var(--warning)", padding: "8px 12px" }}>
          <span style={{ fontSize: 11, color: "var(--text-muted)" }}>Generating LLM directions…</span>
        </div>
      )}
      {mode === "1" && directions !== null && directions.length > 0 && (
        <div className="card" style={{ borderLeft: "3px solid var(--warning)" }}>
          <div className="card-title" style={{ marginBottom: 8 }}>
            Suggested Directions <span style={{ fontSize: 10, color: "var(--text-muted)" }}>(LLM — grounded in the numbers below)</span>
          </div>
          {directions.map((d, i) => (
            <div key={i} style={{ marginBottom: 10, paddingBottom: 10, borderBottom: i < directions.length - 1 ? "1px solid var(--border)" : "none" }}>
              <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 2 }}>{i + 1}. {d.title}</div>
              <div style={{ fontSize: 12, color: "var(--text-muted)", marginBottom: 6 }}>{d.why}</div>
              <div style={{ display: "flex", flexWrap: "wrap", gap: 4 }}>
                {(d.needles || []).map((n) => (
                  <button
                    key={n}
                    className="btn btn-sm clickable-tint"
                    style={{ fontFamily: "monospace", fontSize: 10 }}
                    onClick={() => searchNeedle(n, d.family || undefined)}
                  >
                    {n}
                  </button>
                ))}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Top-line stats */}
      <div style={{ display: "flex", gap: 12, flexWrap: "wrap", marginBottom: 4 }}>
        <div className="card" style={{ flex: 1, minWidth: 140 }}>
          <div style={{ fontSize: 22, fontWeight: 700 }}>{brief.total_files}</div>
          <div style={{ fontSize: 11, color: "var(--text-muted)" }}>parsed files</div>
        </div>
        <div className="card" style={{ flex: 1, minWidth: 140 }}>
          <div style={{ fontSize: 22, fontWeight: 700 }}>{(brief.total_rows || 0).toLocaleString()}</div>
          <div style={{ fontSize: 11, color: "var(--text-muted)" }}>evidence rows</div>
        </div>
        <div className="card" style={{ flex: 1, minWidth: 140 }}>
          <div style={{ fontSize: 22, fontWeight: 700, color: alerts.length ? "var(--danger)" : undefined }}>
            {brief.alert_count}
          </div>
          <div style={{ fontSize: 11, color: "var(--text-muted)" }}>crit/high alerts</div>
        </div>
        <div className="card" style={{ flex: 1, minWidth: 140 }}>
          <div style={{ fontSize: 22, fontWeight: 700 }}>{scan.length}</div>
          <div style={{ fontSize: 11, color: "var(--text-muted)" }}>needles with hits</div>
        </div>
        <div className="card" style={{ flex: 1, minWidth: 140 }}>
          <div style={{ fontSize: 22, fontWeight: 700 }}>{brief.hosts?.length || 0}</div>
          <div style={{ fontSize: 11, color: "var(--text-muted)" }}>hosts</div>
        </div>
      </div>

      <div style={{ display: "flex", gap: 12, flexWrap: "wrap", alignItems: "flex-start" }}>
        <div style={{ flex: "2 1 420px", minWidth: 320 }}>
          {/* Alerts — what the signatures already caught */}
          <div className="card">
            <div className="card-title" style={{ marginBottom: 8 }}>
              Alert Surface <span style={{ fontSize: 10, color: "var(--text-muted)" }}>(Hayabusa / Sigma severity)</span>
            </div>
            {alerts.length === 0 ? (
              <p style={{ fontSize: 12, color: "var(--text-muted)" }}>No critical/high severity rows in the scanned hits.</p>
            ) : (
              <table style={{ width: "100%", borderCollapse: "collapse" }}>
                <tbody>
                  {alerts.slice(0, 20).map((a, i) => {
                    const it = a.interpret;
                    const open = openAlert === i;
                    return (
                      <tr key={i} style={{ borderBottom: "1px solid var(--border)", verticalAlign: "top" }}>
                        <td colSpan={3} style={{ padding: 0 }}>
                          <div
                            style={{ display: "flex", cursor: "pointer", padding: "4px 6px" }}
                            onClick={() => setOpenAlert(open ? null : i)}
                            title={it ? "click for what this means + what to check next" : "click to search this alert"}
                          >
                            <span className={`badge ${a.level === "critical" ? "danger" : "draft"}`}
                                  style={{ fontSize: 9, width: 54, flexShrink: 0 }}>
                              {a.level.toUpperCase()}
                            </span>
                            <span style={{ fontSize: 11, flex: 1, padding: "0 6px" }}>
                              {a.title || "(untitled rule)"}
                            </span>
                            <span style={{ fontSize: 10, color: "var(--text-muted)", width: 150, flexShrink: 0 }}>
                              {a.host} · {a.time.slice(0, 19)}
                            </span>
                            <span style={{ fontSize: 10, color: "var(--text-muted)", width: 14 }}>{open ? "▾" : "▸"}</span>
                          </div>
                          {open && (
                            <div style={{
                              padding: "6px 10px 8px 66px", fontSize: 11,
                              borderTop: "1px dashed var(--border)",
                            }}>
                              {it?.meaning && <div style={{ marginBottom: 4 }}>{it.meaning}</div>}
                              {it?.learn && it.learn.why_matters.length > 0 && (
                                <div style={{
                                  marginBottom: 6, padding: "6px 8px",
                                  background: "var(--bg-tertiary)", borderRadius: 4,
                                }}>
                                  <strong style={{ color: "var(--text-secondary)" }}>Why this matters:</strong>{" "}
                                  <span>{it.learn.headline}</span>
                                  <ul style={{ margin: "2px 0 0 16px", padding: 0, color: "var(--text-muted)" }}>
                                    {it.learn.why_matters.slice(0, 3).map((w, wi) => <li key={wi}>{w}</li>)}
                                  </ul>
                                </div>
                              )}
                              {it && (it.skills || []).length > 0 && (
                                <div style={{ marginBottom: 6 }}>
                                  <strong style={{ color: "var(--text-secondary)" }}>Guided steps:</strong>
                                  {(it.skills || []).map((sk, si) => (
                                    <div key={si} style={{
                                      margin: "4px 0 0 0", padding: "4px 8px",
                                      borderLeft: "2px solid var(--accent)", background: "var(--bg-subtle, transparent)",
                                    }}>
                                      <div style={{ fontSize: 11, fontWeight: 600 }}>
                                        {sk.title || sk.name}
                                        {sk.mitre?.length > 0 && (
                                          <span style={{ fontSize: 9, color: "var(--text-muted)", marginLeft: 6 }}>
                                            {sk.mitre.join(", ")}
                                          </span>
                                        )}
                                      </div>
                                      {sk.why && sk.why.length > 0 && (
                                        <div style={{ fontSize: 10, color: "var(--text-muted)" }}>
                                          matched: {sk.why.join(" · ")}
                                        </div>
                                      )}
                                      {(sk.confirm || []).slice(0, 3).map((c, ci) => (
                                        <div key={ci} style={{ fontSize: 10, marginTop: 2 }}>
                                          <span style={{ color: "var(--success, #2f9e44)" }}>confirm:</span>{" "}
                                          {c.look_for || c.corroborate}
                                          {c.query && (
                                            <button className="btn btn-sm clickable-tint"
                                                    style={{ fontFamily: "monospace", fontSize: 9, marginLeft: 4, padding: "0 4px" }}
                                                    onClick={(e) => { e.stopPropagation(); searchNeedle(c.query, a.family); }}>
                                              {c.query.length > 32 ? c.query.slice(0, 32) + "…" : c.query}
                                            </button>
                                          )}
                                        </div>
                                      ))}
                                      {sk.refute && (
                                        <div style={{ fontSize: 10, marginTop: 2 }}>
                                          <span style={{ color: "var(--text-muted)" }}>refute:</span>{" "}
                                          <span style={{ color: "var(--text-muted)" }}>{sk.refute}</span>
                                        </div>
                                      )}
                                    </div>
                                  ))}
                                </div>
                              )}
                              {it && it.look_for.length > 0 && (
                                <div style={{ marginBottom: 4 }}>
                                  <strong style={{ color: "var(--text-secondary)" }}>Check next:</strong>
                                  <ul style={{ margin: "2px 0 0 16px", padding: 0 }}>
                                    {it.look_for.slice(0, 4).map((lf, j) => <li key={j}>{lf}</li>)}
                                  </ul>
                                </div>
                              )}
                              {it && it.next_queries.length > 0 && (
                                <div style={{ marginBottom: 4 }}>
                                  <strong style={{ color: "var(--text-secondary)" }}>Run:</strong>{" "}
                                  {it.next_queries.slice(0, 4).map((q) => (
                                    <button key={q} className="btn btn-sm clickable-tint"
                                            style={{ fontFamily: "monospace", fontSize: 10, marginRight: 4 }}
                                            onClick={(e) => { e.stopPropagation(); searchNeedle(q, a.family); }}>
                                      {q.length > 40 ? q.slice(0, 40) + "." : q}
                                    </button>
                                  ))}
                                </div>
                              )}
                              {it && it.caveats.length > 0 && (
                                <div style={{ fontSize: 10, color: "var(--warning)" }}>
                                  {it.caveats.slice(0, 3).map((c, j) => <div key={j}>⚠ {c}</div>)}
                                </div>
                              )}
                              {!it && (
                                <button className="btn btn-sm clickable-tint" style={{ fontSize: 10 }}
                                        onClick={(e) => { e.stopPropagation(); searchNeedle(a.title || a.family, a.family); }}>
                                  Search this alert in Explore 
                                </button>
                              )}
                            </div>
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            )}
          </div>

          {/* Signal map — playbook auto-scan needle → hit count */}
          <div className="card">
            <div className="card-title" style={{ marginBottom: 8 }}>
              Signal Map <span style={{ fontSize: 10, color: "var(--text-muted)" }}>({brief.scanned_needles} playbook/ATT&CK/Sigma needles scanned)</span>
            </div>
            {scan.length === 0 ? (
              <p style={{ fontSize: 12, color: "var(--text-muted)" }}>
                No playbook needles matched. Try the Explore page with your own terms.
              </p>
            ) : (
              <>
                <div style={{ display: "flex", flexWrap: "wrap", gap: 4 }}>
                  {signalScan.slice(0, 60).map((s) => (
                    <button
                      key={s.needle}
                      className="btn btn-sm clickable-tint"
                      style={{ fontFamily: "monospace", fontSize: 11 }}
                      title={`${s.hits}${brief.scan_truncated ? "+" : ""} hits — ${s.source} — click to open in Explore`}
                      onClick={() => searchNeedle(s.needle)}
                    >
                      {s.needle} <strong>{s.hits}{brief.scan_truncated ? "+" : ""}</strong>
                    </button>
                  ))}
                </div>
                {brief.scan_truncated && (
                  <div style={{ fontSize: 10, color: "var(--warning)", marginTop: 6 }}>
                    Counts are LOWER BOUNDS
                    {truncReasons.length > 0 && ` — ${truncReasons.join("; ")}`}
                    {truncReasons.length === 0 && " — the scan stopped at the briefing window"}
                    ; Explore shows the true total.
                  </div>
                )}
              </>
            )}
            {facts.length > 0 && (
              <div style={{ marginTop: 10, borderTop: "1px solid rgba(128,128,128,0.3)", paddingTop: 8 }}>
                <div
                  style={{ fontSize: 10, color: "var(--text-muted)", marginBottom: 4 }}
                  title="Keyword matches on id/label columns (EventId, RecordNumber, Provider, Level...). They show the value exists in the evidence — useful pivots, never suspicious signal or findings."
                >
                  Field facts — id/label column matches (not signal)
                </div>
                <div style={{ display: "flex", flexWrap: "wrap", gap: 10 }}>
                  {facts.slice(0, 40).map((f) => (
                    <span
                      key={`${f.needle}:${f.field || ""}`}
                      style={{ fontFamily: "monospace", fontSize: 11, color: "var(--text-muted)" }}
                      title={`${f.hits} row(s) matched ${f.field || "a field"} (${f.class || "fact"}) — the value exists in the evidence, it is not evidence of behaviour`}
                    >
                      {f.needle}
                      {f.field ? ` · ${f.field}` : ""} <strong>{f.hits}</strong>
                    </span>
                  ))}
                </div>
              </div>
            )}
            {itmCoverage.length > 0 && (
              <div style={{ marginTop: 10, borderTop: "1px solid rgba(128,128,128,0.3)", paddingTop: 8 }}>
                <div
                  style={{ fontSize: 10, color: "var(--text-muted)", marginBottom: 4 }}
                  title="Insider Threat Matrix packs relevant to this case's families. 0 hits is negative evidence for those artifacts, not absence of risk — caveats apply."
                >
                  Insider Threat Matrix coverage — pack hits (not evidence)
                </div>
                <div style={{ display: "flex", flexWrap: "wrap", gap: 10 }}>
                  {itmCoverage.slice(0, 10).map((r) => (
                    <span
                      key={r.itm}
                      style={{
                        fontFamily: "monospace",
                        fontSize: 11,
                        color: r.hits ? "var(--text)" : "var(--text-muted)",
                      }}
                      title={`${r.name}${r.caveat ? ` — ${r.caveat}` : ""}`}
                    >
                      {r.itm} {r.name} <strong>{r.hits}</strong>
                      {r.strong_hits ? ` (${r.strong_hits} strong)` : ""}
                    </span>
                  ))}
                </div>
              </div>
            )}
            {backgroundTerms.length > 0 && (
              <div
                style={{ marginTop: 8, fontSize: 10, color: "var(--text-muted)" }}
                title={`Terms matching >= ${brief.ubiquity_floor || 0} rows of this case — background noise, ranked last and never staged as findings.`}
              >
                Background terms (ubiquitous):{" "}
                {backgroundTerms
                  .slice(0, 12)
                  .map((s) => `${s.needle} (${s.hits})`)
                  .join(" · ")}
              </div>
            )}
          </div>
        </div>

        <div style={{ flex: "1 1 300px", minWidth: 260 }}>
          {/* Evidence inventory */}
          <div className="card">
            <div className="card-title" style={{ marginBottom: 8 }}>Evidence Inventory</div>
            <table style={{ width: "100%", borderCollapse: "collapse" }}>
              <tbody>
                {Object.entries(inv).sort((a, b) => b[1].rows - a[1].rows).map(([fam, e]) => (
                  <tr key={fam} className="vt-clickable-row" style={{ borderBottom: "1px solid var(--border)", cursor: "pointer" }}
                      onClick={() => navigate(`/explore?family=${fam}`)}>
                    <td style={{ padding: "4px 6px", fontFamily: "monospace", fontSize: 11 }}>{fam}</td>
                    <td style={{ padding: "4px 6px", fontSize: 11, textAlign: "right" }}>
                      {e.rows.toLocaleString()}{e.capped ? "+" : ""} rows · {e.files} files
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {brief.hosts && brief.hosts.length > 0 && (
              <div style={{ marginTop: 8, fontSize: 11, color: "var(--text-muted)" }}>
                Hosts: {brief.hosts.slice(0, 10).join(", ")}
              </div>
            )}
            {brief.time_range?.start && (
              <div style={{ marginTop: 4, fontSize: 11, color: "var(--text-muted)" }}>
                {brief.time_range.start.slice(0, 19)} → {brief.time_range.end?.slice(0, 19)}
              </div>
            )}
          </div>

          {/* Parser ledger */}
          <div className="card">
            <div className="card-title" style={{ marginBottom: 8 }}>
              Parser Lane <span style={{ fontSize: 10, color: "var(--text-muted)" }}>{ledger.ok} OK · {ledger.skip} skip · {ledger.fail} fail</span>
            </div>
            <div style={{ maxHeight: 200, overflowY: "auto" }}>
              {ledger.entries.slice(0, 30).map((e, i) => (
                <div key={i} style={{ fontSize: 10, padding: "2px 0", display: "flex", gap: 6 }}>
                  <span style={{
                    color: e.status === "OK" ? "var(--success)" : e.status.startsWith("SKIP") ? "var(--text-muted)" : "var(--danger)",
                    width: 40, flexShrink: 0, fontFamily: "monospace",
                  }}>
                    {e.status}
                  </span>
                  <span style={{ fontFamily: "monospace" }}>{e.tool}</span>
                  {e.reason && <span style={{ color: "var(--text-muted)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{e.reason}</span>}
                </div>
              ))}
            </div>
          </div>

          {/* Top entities */}
          {Object.keys(entities).length > 0 && (
            <div className="card">
              <div className="card-title" style={{ marginBottom: 8 }}>Top Entities</div>
              {Object.entries(entities).map(([etype, list]) => (
                <div key={etype} style={{ marginBottom: 6 }}>
                  <div style={{ fontSize: 10, color: "var(--text-muted)", textTransform: "uppercase" }}>{etype}</div>
                  <div style={{ display: "flex", flexWrap: "wrap", gap: 3, marginTop: 2 }}>
                    {list.slice(0, 6).map((e) => (
                      <button
                        key={e.value}
                        className="btn btn-sm clickable-tint"
                        style={{ fontFamily: "monospace", fontSize: 10, padding: "1px 6px" }}
                        title={`${e.hits} hits across ${(e.families || []).join(", ")}${e.source_file ? ` — e.g. ${e.source_file}` : ""}`}
                        onClick={() => searchNeedle(e.value)}
                      >
                        {e.value}
                      </button>
                    ))}
                  </div>
                </div>
              ))}
              {brief.paths_summary && brief.paths_summary.distinct > 0 && (
                <div style={{ marginTop: 8, fontSize: 10, color: "var(--text-muted)" }}>
                  Host filesystem paths inside evidence content:{" "}
                  <strong>{brief.paths_summary.distinct}</strong> distinct
                  {brief.paths_summary.families?.length
                    ? ` (${brief.paths_summary.families.join(", ")})`
                    : ""}{" "}
                  — content paths, not evidence files.
                  {brief.paths_summary.examples?.length
                    ? ` e.g. ${brief.paths_summary.examples.join(", ")}`
                    : ""}
                </div>
              )}
            </div>
          )}
        </div>
      </div>

      <div style={{ marginTop: 12, fontSize: 12, color: "var(--text-muted)" }}>
        Backend: {brief.backend || "csv"} · {brief.hits_examined} hits examined ·{" "}
        <Link to="/explore" style={{ color: "var(--accent)" }}>Open Explore →</Link>
      </div>

      {/* WP 4j.5c — offline copies: the briefing + full signal map persist to the
          case dir on every render so the examiner can review them without the UI. */}
      {brief.artifacts?.briefing_md && (
        <div style={{ marginTop: 6, fontSize: 11, color: "var(--text-muted)" }}>
          Offline copies (rebuilt each view — open these if the UI misbehaves):{" "}
          <code style={{ color: "var(--text-primary)" }}>{brief.artifacts.briefing_md}</code>
          {brief.artifacts.signal_map_csv && (
            <>{" · "}<code style={{ color: "var(--text-primary)" }}>{brief.artifacts.signal_map_csv}</code></>
          )}
        </div>
      )}
    </div>
  );
}
