/**
 * Briefing — WP 4i.4. The examiner's first view of a processed case.
 *
 * What was collected (inventory + parser ledger), what the detections and
 * baselines raised (the alert surface: every crit/high lead), the typed
 * entities, hosts, time range, and the intake echo. Deterministic — no LLM
 * required. Keyword pivots are the examiner's own, in Explore and the query
 * pack: a word count is never shown as signal (Part 12 FM-3, D460).
 */
import { useEffect, useRef, useState } from "react";
import styles from "./Briefing.module.css";
import { useNavigate, Link } from "react-router-dom";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import { api, type BriefingDirection, type BriefingResponse, type CaseDigestResponse, type InterpretRoundsResponse } from "../api/client";
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
  // WO-1C item 3 — context policy, recorded on the run. `independent` sees
  // evidence/leads/digest only; `informed` also passes prior reports and DRAFT
  // summaries as labelled examiner context (never as evidence).
  const [contextPolicy, setContextPolicy] = useState<"independent" | "informed">(
    "independent",
  );
  // WP 4j.1: alert rows expand to show interpretation (meaning + what to check)
  const [openAlert, setOpenAlert] = useState<number | null>(null);
  // WP 4j.3: guided first-pass step completion (per-case, local)
  const [doneSteps, setDoneSteps] = useState<Record<string, boolean>>({});

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
        context: contextPolicy,
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

  const ledger = brief.ledger || { entries: [], ok: 0, skip: 0, fail: 0 };
  const inv = brief.inventory || {};
  const alerts = brief.alerts || [];
  const entities = brief.entities || {};
  const intake = brief.intake || {};
  const walkthrough = brief.walkthrough || [];

  return (
    <div>
      <div className={styles.s1}>
        <h2 className={styles.s2}>Case Briefing</h2>
      </div>
      <p className={styles.s5}>
        Auto-generated after processing — what was collected, what the signatures
        already caught, and where to start digging.
      </p>

      {/* Mode 1 (LLM) — question-driven interpretation run with the live feed */}
      {mode === "1" && (
        <div className={`card ${styles.s6}`}>
          <div className={`card-title ${styles.s7}`}>
            Mode 1 — LLM interpretation run (coverage)
          </div>
          <div className={styles.s8}>
            The deterministic lane parses and indexes, then the LLM interprets every entity
            against RAG methodology and threat intel, and stages DRAFT findings for your approval.
          </div>
          <textarea
            value={modeQuestion}
            onChange={(e) => setModeQuestion(e.target.value)}
            placeholder="Examiner question for the interpretation (e.g. 'What did D:\\m.exe do and is it malicious?') — drives the LLM analysis"
            rows={2}
            className={styles.s9}
            disabled={modeRunStatus === "running"}
          />
          <div className={styles.s10}>
            <label className={styles.s11}
              title="Interpretation rounds: how many orient → verify → reconcile passes the LLM loop runs (1–5).">
              rounds
              <input
                type="number" min={1} max={5} value={interpretRounds}
                onChange={(e) => setInterpretRounds(Math.max(1, Math.min(5, Number(e.target.value) || 3)))}
                disabled={modeRunStatus === "running"}
                className={styles.s12}
              />
            </label>
            <label className={styles.s11}
              title="Context policy: independent = evidence, leads and digest only. informed = also passes prior reports and DRAFT summaries as labelled examiner context, never as evidence.">
              context
              <select
                value={contextPolicy}
                onChange={(e) => setContextPolicy(e.target.value as "independent" | "informed")}
                disabled={modeRunStatus === "running"}
                className={styles.s12}
              >
                <option value="independent">independent (evidence only)</option>
                <option value="informed">informed (+ prior findings)</option>
              </select>
            </label>
            <label className={styles.s11}
              title="Your model's max context window (tokens). The context allocator packs window × 0.7 so interpretation sees as much of the case as the model can hold.">
              context window
              <input
                type="number" min={8000} step={100000} value={contextWindow}
                onChange={(e) => setContextWindow(Math.max(8000, Number(e.target.value) || 1_000_000))}
                disabled={modeRunStatus === "running"}
                className={styles.s13}
              />
              tokens
            </label>
          </div>
          <div className={styles.s14}>
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
              <span className={styles.s15}>
                Complete — DRAFT findings staged (review in Approve)
              </span>
            )}
            {modeRunError && <span className={styles.s16}>{modeRunError}</span>}
          </div>
          {modeStages.length > 0 && (
            <div className={styles.s17}>
              {modeStages.slice(-14).map((s, i) => (
                <div key={i}>
                  <span className={s.status === "error" ? styles.stageError : s.status === "running" ? styles.stageRunning : styles.stageIdle}>
                    [{s.stage || s.tool || "?"}]
                  </span>{" "}
                  {s.status || ""}{s.detail ? ` — ${s.detail}` : ""}
                </div>
              ))}
            </div>
          )}
          {modeRunId && (
            <div className={styles.s18}>
              run {modeRunId}
            </div>
          )}
        </div>
      )}

      {/* Mode 2/3 — the depths run from Agent Run; the lane is the prerequisite */}
      {(mode === "2" || mode === "3") && (
        <div className={`card ${styles.s19}`}>
          <div className={`card-title ${styles.s7}`}>
            {mode === "2" ? "Mode 2 — Multi-role runs from Agent Run" : "Mode 3 — Multi-agent runs from Agent Run"}
          </div>
          <div className={styles.s8}>
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
        <div className={`card ${styles.s6}`}>
          <div className={`card-title ${styles.s7}`}>
            Case Digest{" "}
            <span className={styles.s20}>
              (deterministic — everything the interpretation must reconcile)
            </span>
          </div>
          {digestError && <div className={styles.s16}>{digestError}</div>}
          {!digest && !digestError && (
            <span className={styles.s21}>Building digest…</span>
          )}
          {digest && (() => {
            const d = digest.digest;
            return (
              <>
                <div className={styles.s22}>
                  {(d.alerts || []).length} high/critical alert(s) ·{" "}
                  {d.hosts?.length ?? 0} host(s) · {Object.keys(d.inventory || {}).length} famil{Object.keys(d.inventory || {}).length === 1 ? "y" : "ies"} ·{" "}
                  timeline: {d.timeline?.source || "n/a"}
                </div>
                {(d.scope?.explicitly_absent?.length ?? 0) > 0 && (
                  <div className={styles.s23}>
                    Scope — NOT in evidence (stated as scope, never as “no compromise”):{" "}
                    {d.scope.explicitly_absent.join("; ")}
                  </div>
                )}
                {(d.scope?.evidence_classes_present?.length ?? 0) > 0 && (
                  <div className={styles.s24}>
                    In evidence: {d.scope.evidence_classes_present.join(", ")}
                  </div>
                )}
                {digest.markdown && (
                  <details>
                    <summary className={styles.s25}>
                      Full digest (what the LLM was given)
                    </summary>
                    <div className={styles.s26}>
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
        <div className={`card ${styles.s6}`}>
          <div className={`card-title ${styles.s7}`}>
            Interpretation rounds{" "}
            <span className={styles.s20}>
              (Orient → Verify → Reconcile — replay of how the LLM got there)
            </span>
          </div>
          <div className={styles.s22}>
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
            <ul className={styles.s27}>
              {rounds.summary.hypotheses.map((h) => (
                <li key={h.id}>
                  <b>{h.id}</b>: {h.statement}
                  {h.why ? <span className={styles.s28}> — {h.why}</span> : null}
                </li>
              ))}
            </ul>
          )}
          {rounds.summary.reconciliation.unaddressed.length > 0 && (
            <div className={styles.s29}>
              Still unaddressed (verdict must state these as open):{" "}
              {rounds.summary.reconciliation.unaddressed.map((u) => `[${u.kind}] ${u.value}`).join("; ")}
            </div>
          )}
          <details>
            <summary className={styles.s25}>
              Round detail ({rounds.rounds.length} artifact(s))
            </summary>
            <div className={styles.s30}>
              {rounds.rounds.map((r) => (
                <div key={`${r.round}-${r.kind}`} className={styles.s31}>
                  <div className={styles.s32}>
                    Round {r.round} — {r.kind}
                  </div>
                  {r.entries && r.entries.length > 0 && (
                    <ul className={styles.s33}>
                      {r.entries.map((e, i) => (
                        <li key={i}>
                          <span className={styles.s34}>{e.kind}</span>:{" "}
                          {String((e.params?.dsl as string) || e.params?.value || "")}
                          {e.error ? ` — ERROR: ${e.error}` : ` — ${e.count ?? 0} row(s)`}
                          {e.why ? <span className={styles.s28}> ({e.why})</span> : null}
                          {e.audit_id ? <span className={styles.s28}> [{e.audit_id}]</span> : null}
                        </li>
                      ))}
                    </ul>
                  )}
                  {r.notes && r.notes.length > 0 && (
                    <ul className={styles.s33}>
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
        <div className={`card ${styles.s6}`}>
          <div className={`card-title ${styles.s7}`}>Mode 2 Interpretation (LLM)</div>
          <article className="report-markdown">
            <ReactMarkdown remarkPlugins={[remarkGfm]}>{brief.mode_interpretation}</ReactMarkdown>
          </article>
        </div>
      )}
      {(mode === "2" || mode === "3") && !brief.mode_interpretation && (brief.findings_summary?.count ?? 0) > 0 && (
        <div className="card">
          <div className={`card-title ${styles.s7}`}>
            Staged findings ({brief.findings_summary?.count} · {brief.findings_summary?.drafts} DRAFT)
          </div>
          <ul className={styles.s35}>
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
          <div className={`card-title ${styles.s7}`}>Threat intel (context)</div>
          <article className="report-markdown">
            <ReactMarkdown remarkPlugins={[remarkGfm]}>{brief.ti_context}</ReactMarkdown>
          </article>
        </div>
      )}

      {/* WP 4j.3 — guided first pass: the walkthrough an examiner follows (Mode 1) */}
      {mode === "1" && walkthrough.length > 0 && (
        <div className={`card ${styles.s36}`}>
          <div className={`card-title ${styles.s41}`}>
            Guided First Pass
            <span className={styles.s42}>
              {Object.values(doneSteps).filter(Boolean).length}/{walkthrough.length} steps done
            </span>
          </div>
          <p className={styles.s43}>
            Work top-down: triage what the signatures caught, map who/where,
            then run the starting points.
          </p>
          {walkthrough.map((st) => {
            const done = !!doneSteps[st.key];
            return (
              <div key={st.key} className={done ? styles.stepDone : styles.step}>
                <input
                  type="checkbox"
                  checked={done}
                  onChange={() => toggleStep(st.key)}
                  className={styles.s44}
                />
                <div className={styles.s45}>
                  <div className={styles.s46}>
                    {st.order}. {st.title}
                    <span className={`badge ${styles.s47}`}>{st.count}</span>
                    {done && <span className={styles.s48}>done</span>}
                  </div>
                  <div className={styles.s49}>{st.why}</div>
                  {st.learn && (st.learn.headline || st.learn.why_matters.length > 0) && (
                    <div className={styles.s50}>
                      {st.learn.headline && (
                        <div className={styles.s51}>Why this matters: {st.learn.headline}</div>
                      )}
                      {st.learn.why_matters.length > 0 && (
                        <ul className={styles.s52}>
                          {st.learn.why_matters.map((w, wi) => <li key={wi}>{w}</li>)}
                        </ul>
                      )}
                    </div>
                  )}
                  {st.actions.length > 0 && (
                    <div className={styles.s53}>
                      {st.actions.map((a, ai) => (
                        <button
                          key={ai}
                          className={`btn btn-sm clickable-tint ${styles.s54}`}
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
          <p className={styles.s55}>
            When the steps stop being obvious, switch to Steer Chat and ask your
            own questions — you are the driver.
          </p>
        </div>
      )}

      {/* Intake echo — what the examiner said they were looking for */}
      {(intake.question || intake.subjects || intake.hypothesis) && (
        <div className={`card ${styles.s36}`}>
          <div className={`card-title ${styles.s56}`}>Investigation Focus</div>
          {intake.question && <div className={styles.s57}><strong>Question:</strong> {intake.question}</div>}
          {intake.subjects && <div className={styles.s57}><strong>Subjects:</strong> {intake.subjects}</div>}
          {intake.hypothesis && <div className={styles.s58}><strong>Hypothesis:</strong> {intake.hypothesis}</div>}
        </div>
      )}

      {/* WP 4i.5 — LLM investigation directions grounded in the deterministic numbers (Mode 1) */}
      {mode === "1" && directions === null && (
        <div className={`card ${styles.s59}`}>
          <span className={styles.s21}>Generating LLM directions…</span>
        </div>
      )}
      {mode === "1" && directions !== null && directions.length > 0 && (
        <div className={`card ${styles.s60}`}>
          <div className={`card-title ${styles.s56}`}>
            Suggested Directions <span className={styles.s20}>(LLM — grounded in the numbers below)</span>
          </div>
          {directions.map((d, i) => (
            <div key={i} className={i < directions.length - 1 ? styles.direction : styles.directionLast}>
              <div className={styles.s61}>{i + 1}. {d.title}</div>
              <div className={styles.s62}>{d.why}</div>
              <div className={styles.s53}>
                {(d.needles || []).map((n) => (
                  <button
                    key={n}
                    className={`btn btn-sm clickable-tint ${styles.s54}`}
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
      <div className={styles.s63}>
        <div className={`card ${styles.s64}`}>
          <div className={styles.s65}>{brief.total_files}</div>
          <div className={styles.s21}>parsed files</div>
        </div>
        <div className={`card ${styles.s64}`}>
          <div className={styles.s65}>{(brief.total_rows || 0).toLocaleString()}</div>
          <div className={styles.s21}>evidence rows</div>
        </div>
        <div className={`card ${styles.s64}`}>
          <div className={alerts.length ? styles.alertHot : styles.alertQuiet}>
            {brief.alert_count}
          </div>
          <div className={styles.s21}>crit/high alerts</div>
        </div>
        <div className={`card ${styles.s64}`}>
          <div className={styles.s65}>{brief.lead_counts?.total ?? 0}</div>
          <div className={styles.s21}>leads to review</div>
        </div>
        <div className={`card ${styles.s64}`}>
          <div className={styles.s65}>{brief.hosts?.length || 0}</div>
          <div className={styles.s21}>hosts</div>
        </div>
      </div>

      <div className={styles.s66}>
        <div className={styles.s67}>
          {/* Alerts — what the signatures already caught */}
          <div className="card">
            <div className={`card-title ${styles.s56}`}>
              Alert Surface <span className={styles.s20}>(Hayabusa / Sigma severity)</span>
            </div>
            {alerts.length === 0 ? (
              <p className={styles.s68}>No critical/high severity rows in the scanned hits.</p>
            ) : (
              <table className={styles.s69}>
                <tbody>
                  {alerts.slice(0, 20).map((a, i) => {
                    const it = a.interpret;
                    const open = openAlert === i;
                    return (
                      <tr key={i} className={styles.s70}>
                        <td colSpan={3} className={styles.s71}>
                          <div
                            className={styles.s72}
                            onClick={() => setOpenAlert(open ? null : i)}
                            title={it ? "click for what this means + what to check next" : "click to search this alert"}
                          >
                            <span className={`badge ${a.level === "critical" ? "danger" : "draft"} ${styles.s73}`}>
                              {a.level.toUpperCase()}
                            </span>
                            <span className={styles.s74}>
                              {a.title || "(untitled rule)"}
                            </span>
                            <span className={styles.s75}>
                              {a.host} · {a.time.slice(0, 19)}
                            </span>
                            <span className={styles.s76}>{open ? "▾" : "▸"}</span>
                          </div>
                          {open && (
                            <div className={styles.s77}>
                              {it?.meaning && <div className={styles.s41}>{it.meaning}</div>}
                              {it?.learn && it.learn.why_matters.length > 0 && (
                                <div className={styles.s78}>
                                  <strong className={styles.s79}>Why this matters:</strong>{" "}
                                  <span>{it.learn.headline}</span>
                                  <ul className={styles.s52}>
                                    {it.learn.why_matters.slice(0, 3).map((w, wi) => <li key={wi}>{w}</li>)}
                                  </ul>
                                </div>
                              )}
                              {it && (it.skills || []).length > 0 && (
                                <div className={styles.s7}>
                                  <strong className={styles.s79}>Guided steps:</strong>
                                  {(it.skills || []).map((sk, si) => (
                                    <div key={si} className={styles.s80}>
                                      <div className={styles.s81}>
                                        {sk.title || sk.name}
                                        {sk.mitre?.length > 0 && (
                                          <span className={styles.s82}>
                                            {sk.mitre.join(", ")}
                                          </span>
                                        )}
                                      </div>
                                      {sk.why && sk.why.length > 0 && (
                                        <div className={styles.s20}>
                                          matched: {sk.why.join(" · ")}
                                        </div>
                                      )}
                                      {(sk.confirm || []).slice(0, 3).map((c, ci) => (
                                        <div key={ci} className={styles.s83}>
                                          <span className={styles.s84}>confirm:</span>{" "}
                                          {c.look_for || c.corroborate}
                                          {c.query && (
                                            <button className={`btn btn-sm clickable-tint ${styles.s85}`}
                                                    onClick={(e) => { e.stopPropagation(); searchNeedle(c.query, a.family); }}>
                                              {c.query.length > 32 ? c.query.slice(0, 32) + "…" : c.query}
                                            </button>
                                          )}
                                        </div>
                                      ))}
                                      {sk.refute && (
                                        <div className={styles.s83}>
                                          <span className={styles.s28}>refute:</span>{" "}
                                          <span className={styles.s28}>{sk.refute}</span>
                                        </div>
                                      )}
                                    </div>
                                  ))}
                                </div>
                              )}
                              {it && it.look_for.length > 0 && (
                                <div className={styles.s41}>
                                  <strong className={styles.s79}>Check next:</strong>
                                  <ul className={styles.s86}>
                                    {it.look_for.slice(0, 4).map((lf, j) => <li key={j}>{lf}</li>)}
                                  </ul>
                                </div>
                              )}
                              {it && it.next_queries.length > 0 && (
                                <div className={styles.s41}>
                                  <strong className={styles.s79}>Run:</strong>{" "}
                                  {it.next_queries.slice(0, 4).map((q) => (
                                    <button key={q} className={`btn btn-sm clickable-tint ${styles.s87}`}
                                            onClick={(e) => { e.stopPropagation(); searchNeedle(q, a.family); }}>
                                      {q.length > 40 ? q.slice(0, 40) + "." : q}
                                    </button>
                                  ))}
                                </div>
                              )}
                              {it && it.caveats.length > 0 && (
                                <div className={styles.s88}>
                                  {it.caveats.slice(0, 3).map((c, j) => <div key={j}>⚠ {c}</div>)}
                                </div>
                              )}
                              {!it && (
                                <button className={`btn btn-sm clickable-tint ${styles.s89}`}
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
        </div>

        <div className={styles.s97}>
          {/* Evidence inventory */}
          <div className="card">
            <div className={`card-title ${styles.s56}`}>Evidence Inventory</div>
            <table className={styles.s69}>
              <tbody>
                {Object.entries(inv).sort((a, b) => b[1].rows - a[1].rows).map(([fam, e]) => (
                  <tr key={fam} className={`vt-clickable-row ${styles.s98}`}
                      onClick={() => navigate(`/explore?family=${fam}`)}>
                    <td className={styles.s99}>{fam}</td>
                    <td className={styles.s100}>
                      {e.rows.toLocaleString()}{e.capped ? "+" : ""} rows · {e.files} files
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {brief.hosts && brief.hosts.length > 0 && (
              <div className={styles.s101}>
                Hosts: {brief.hosts.slice(0, 10).join(", ")}
              </div>
            )}
            {brief.time_range?.start && (
              <div className={styles.s102}>
                {brief.time_range.start.slice(0, 19)} → {brief.time_range.end?.slice(0, 19)}
              </div>
            )}
          </div>

          {/* Parser ledger */}
          <div className="card">
            <div className={`card-title ${styles.s56}`}>
              Parser Lane <span className={styles.s20}>{ledger.ok} OK · {ledger.skip} skip · {ledger.fail} fail</span>
            </div>
            <div className={styles.s103}>
              {ledger.entries.slice(0, 30).map((e, i) => (
                <div key={i} className={styles.s104}>
                  <span className={e.status === "OK" ? styles.laneOk : e.status.startsWith("SKIP") ? styles.laneSkip : styles.laneFail}>
                    {e.status}
                  </span>
                  <span className={styles.s34}>{e.tool}</span>
                  {e.reason && <span className={styles.s105}>{e.reason}</span>}
                </div>
              ))}
            </div>
          </div>

          {/* Top entities */}
          {Object.keys(entities).length > 0 && (
            <div className="card">
              <div className={`card-title ${styles.s56}`}>Top Entities</div>
              {Object.entries(entities).map(([etype, list]) => (
                <div key={etype} className={styles.s7}>
                  <div className={styles.s106}>{etype}</div>
                  <div className={styles.s107}>
                    {list.slice(0, 6).map((e) => (
                      <button
                        key={e.value}
                        className={`btn btn-sm clickable-tint ${styles.s108}`}
                        title={`${e.hits} hits across ${(e.families || []).join(", ")}${e.source_file ? ` — e.g. ${e.source_file}` : ""}`}
                        onClick={() => searchNeedle(e.value)}
                      >
                        {e.value}
                      </button>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      <div className={styles.s109}>
        <Link to="/explore" className={styles.s110}>Open Explore →</Link>
      </div>

      {/* WP 4j.5c — offline copies: the briefing persists to the
          case dir on every render so the examiner can review them without the UI. */}
      {brief.artifacts?.briefing_md && (
        <div className={styles.s111}>
          Offline copies (rebuilt each view — open these if the UI misbehaves):{" "}
          <code className={styles.s112}>{brief.artifacts.briefing_md}</code>
        </div>
      )}
    </div>
  );
}
