import { useEffect, useState } from "react";
import styles from "./Approve.module.css";
import { useNavigate } from "react-router-dom";
import { api, type Finding } from "../api/client";
import { computeApprovalResponse } from "../lib/crypto";
import { useCase } from "../context/CaseContext";

function l1Class(verdict: string): string {
  switch (verdict.toUpperCase()) {
    case "PROVEN":
      return styles.l1Proven;
    case "UNSUPPORTED":
      return styles.l1Unsupported;
    case "CONTRADICTED":
      return styles.l1Contradicted;
    default:
      return styles.l1Unverifiable;
  }
}

export default function Approve() {
  const { activeCase, refreshStages } = useCase();
  const navigate = useNavigate();
  const [findings, setFindings] = useState<Finding[]>([]);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [password, setPassword] = useState("");
  const [examiner, setExaminer] = useState("");
  const [statusMsg, setStatusMsg] = useState("");
  const [result, setResult] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);

  // Rejection state
  const [rejectMode, setRejectMode] = useState(false);
  const [rejectReason, setRejectReason] = useState("");

  // WO-2: a finding the L1 verifier did not prove needs an explicit override
  // reason, recorded with the approval.
  const [overrideReason, setOverrideReason] = useState("");

  // Readiness probe — which examiner identity will sign, and whether a
  // password is configured at all. Shown up front, not after a failed click.
  const [examinerIdentity, setExaminerIdentity] = useState<string | null>(null);
  const [passwordConfigured, setPasswordConfigured] = useState<boolean | null>(null);
  const [setupHint, setSetupHint] = useState<string | null>(null);

  const load = () => {
    setLoading(true);
    api.findings("DRAFT")
      .then((r) => {
        setFindings(r.findings);
        // Pre-select all drafts by default for quick examiner workflow
        setSelected(new Set(r.findings.map((f) => f.id)));
      })
      .catch((e) => setError((e as Error).message))
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    load();
    api.commitStatus()
      .then((s) => {
        setExaminerIdentity(s.examiner);
        setPasswordConfigured(s.password_configured);
        setSetupHint(s.setup_hint);
      })
      .catch(() => setPasswordConfigured(null));
  }, [activeCase]);

  const toggle = (id: string) => {
    const next = new Set(selected);
    next.has(id) ? next.delete(id) : next.add(id);
    setSelected(next);
  };

  const selectAll = () => setSelected(new Set(findings.map((f) => f.id)));
  const clearSelection = () => setSelected(new Set());

  const verdictOf = (f: Finding) => f.l1?.verdict ?? "UNVERIFIABLE";
  const needsOverride = findings.filter(
    (f) => selected.has(f.id) && verdictOf(f) !== "PROVEN"
  );

  const handleApprove = async () => {
    setError("");
    setResult("");
    if (selected.size === 0) {
      setError("Select at least one finding to approve");
      return;
    }
    if (needsOverride.length > 0 && !overrideReason.trim()) {
      setError(
        `L1 verdict is not PROVEN for ${needsOverride.length} selected finding(s). ` +
        "Enter an override reason — it is recorded with the approval."
      );
      return;
    }
    if (!password) {
      setError(
        "Approval password required — the examiner password set via `nexus config --setup-password`" +
        (examinerIdentity ? ` for identity '${examinerIdentity}'` : "") +
        ". It never leaves this browser: it only derives the local HMAC signature.",
      );
      return;
    }

    setBusy(true);
    try {
      setStatusMsg("Requesting authentication challenge...");
      const ch = await api.getChallenge();

      setStatusMsg(`Deriving HMAC key (${ch.iterations.toLocaleString()} iterations)...`);
      const responseHmac = await computeApprovalResponse(
        password,
        ch.salt,
        ch.iterations,
        ch.nonce
      );

      setStatusMsg("Submitting HMAC approval to verification ledger...");
      const r = await api.commit({
        finding_ids: Array.from(selected),
        challenge_id: ch.challenge_id,
        response: responseHmac,
        examiner: examiner.trim() || undefined,
        override_reasons: Object.fromEntries(
          needsOverride.map((f) => [f.id, overrideReason.trim()])
        ),
      });

      if (r.errors.length > 0) {
        setError(`${r.errors.length} error(s): ${r.errors.map((e) => e.error).join("; ")}`);
      }
      if (r.approved.length > 0) {
        setResult(`✓ Successfully approved ${r.approved.length} finding(s): ${r.approved.join(", ")}`);
        setPassword("");
        setOverrideReason("");
        if (activeCase) refreshStages(activeCase);
        load();
      }
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
      setStatusMsg("");
    }
  };

  const handleReject = async () => {
    setError("");
    setResult("");
    if (selected.size === 0) {
      setError("Select at least one finding to reject");
      return;
    }
    if (!rejectReason.trim()) {
      setError("Rejection reason is required");
      return;
    }

    setBusy(true);
    try {
      setStatusMsg("Rejecting findings...");
      const r = await api.rejectFindings({
        finding_ids: Array.from(selected),
        reason: rejectReason.trim(),
        examiner: examiner.trim() || undefined,
      });

      if (r.ok) {
        setResult(`✗ Rejected ${r.rejected.length} finding(s)`);
        setRejectMode(false);
        setRejectReason("");
        if (activeCase) refreshStages(activeCase);
        load();
      } else {
        setError(r.error || "Failed to reject findings");
      }
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
      setStatusMsg("");
    }
  };

  if (loading) return <div className="loading">Loading DRAFT findings...</div>;

  return (
    <div>
      <div className={styles.s1}>
        <h2>Approval Desk (N6)</h2>
        {findings.length > 0 && (
          <div className={styles.s2}>
            <button className="btn btn-sm" onClick={selectAll}>Select All</button>
            <button className="btn btn-sm" onClick={clearSelection}>Clear</button>
          </div>
        )}
      </div>

      {error && <div className="error-banner">{error}</div>}
      {result && (
        <div className={styles.s3}>
          <span>{result}</span>
          {result.startsWith("✓") && (
            <button
              className={`btn btn-sm ${styles.s4}`}
              onClick={() => navigate("/timeline")}
              title="N7 — review the unified case timeline before generating the report"
            >
              Next: Review Timeline →
            </button>
          )}
        </div>
      )}

      <div className={`card ${styles.s5}`}>
        <div className="card-header">
          <span className="card-title">DRAFT Findings ({findings.length})</span>
          <span className={styles.s6}>{selected.size} selected</span>
        </div>
        {findings.length === 0 ? (
          <div className="empty-state">
            <h3>No DRAFT findings</h3>
            <p>All findings are currently approved or no findings have been staged yet.</p>
          </div>
        ) : (
          <table>
            <thead>
              <tr>
                <th className={styles.s7}></th>
                <th>ID</th>
                <th>Title</th>
                <th>Confidence</th>
                <th>L1</th>
                <th>Source</th>
              </tr>
            </thead>
            <tbody>
              {findings.map((f) => (
                <tr key={f.id}>
                  <td>
                    <input
                      type="checkbox"
                      checked={selected.has(f.id)}
                      onChange={() => toggle(f.id)}
                      className={styles.s8}
                    />
                  </td>
                  <td className={styles.s9}>{f.id}</td>
                  <td>
                    <strong>{f.title}</strong>
                    {f.observation && (
                      <div className={styles.s10}>
                        {f.observation.slice(0, 100)}...
                      </div>
                    )}
                  </td>
                  <td><span className={`badge badge-${f.confidence.toLowerCase()}`}>{f.confidence}</span></td>
                  <td>
                    <span
                      className={`badge ${l1Class(verdictOf(f))}`}
                      title={
                        f.l1?.failing_checks?.length
                          ? f.l1.failing_checks.map((c) => `${c.id}: ${c.detail}`).join("\n")
                          : undefined
                      }
                    >
                      {verdictOf(f)}
                    </span>
                    {(f.l1?.failing_checks ?? []).slice(0, 2).map((c) => (
                      <div key={c.id} className={styles.s11}>
                        {c.id}: {c.detail.slice(0, 80)}
                      </div>
                    ))}
                  </td>
                  <td>{f.examiner_selected === false ? "LLM-drafted" : "examiner"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {findings.length > 0 && (
        <div className="card">
          <div className="card-header">
            <span className="card-title">Cryptographic Human Approval (FD-002)</span>
          </div>
          <div className={styles.s12}>
            <p className={styles.s13}>
              Approving signs a PBKDF2-HMAC-SHA256 entry to the immutable ledger.
              Enter the <strong>examiner approval password</strong>
              {examinerIdentity ? ` for identity '${examinerIdentity}'` : ""} — the one
              set with <code>nexus config --setup-password</code>. It never leaves this
              browser: Web Crypto derives the signature locally, and the server sees
              only an HMAC of a one-time challenge.
            </p>

            {passwordConfigured === false && (
              <div className={`error-banner ${styles.s14}`}>
                No approval password is configured
                {examinerIdentity ? ` for '${examinerIdentity}'` : ""} — approving will
                fail. Set one first: <code>{setupHint || "nexus config --setup-password"}</code>
              </div>
            )}

            <div>
              <label className={styles.s15}>
                Examiner Identity (optional override)
              </label>
              <input
                placeholder="Default from active config"
                value={examiner}
                onChange={(e) => setExaminer(e.target.value)}
                disabled={busy}
              />
            </div>

            <div>
              <label className={styles.s15}>
                Approval Password
              </label>
              <input
                type="password"
                placeholder={
                  passwordConfigured === false
                    ? "No password configured yet — see warning above"
                    : "Examiner approval password (nexus config --setup-password)"
                }
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && handleApprove()}
                disabled={busy}
              />
            </div>

            {needsOverride.length > 0 && (
              <div>
                <label className={styles.s16}>
                  Override Reason (required — L1 not PROVEN for {needsOverride.length} selected)
                </label>
                <input
                  placeholder="e.g. Verifier could not replay the count; examiner confirmed against the raw rows"
                  value={overrideReason}
                  onChange={(e) => setOverrideReason(e.target.value)}
                  disabled={busy}
                />
                <div className={styles.s17}>
                  {needsOverride.map((f) => `${f.id}: ${verdictOf(f)}`).join(" · ")}
                </div>
              </div>
            )}

            {statusMsg && (
              <div className={styles.s18}>
                ⚡ {statusMsg}
              </div>
            )}

            <div className={styles.s19}>
              <button
                className={`btn btn-primary ${styles.s20}`}
                onClick={handleApprove}
                disabled={busy || selected.size === 0 || (needsOverride.length > 0 && !overrideReason.trim())}
                title={!password ? "Enter the examiner approval password first — click for details" : undefined}
              >
                {busy ? "Signing..." : `Approve ${selected.size} Finding(s)`}
              </button>
              <button
                className="btn btn-secondary"
                onClick={() => setRejectMode(!rejectMode)}
                disabled={busy || selected.size === 0}
              >
                Reject...
              </button>
            </div>

            {rejectMode && (
              <div className={styles.s21}>
                <label className={styles.s16}>
                  Reason for Rejection (required by FD-001)
                </label>
                <input
                  placeholder="e.g. Legitimate administrative activity, baseline software"
                  value={rejectReason}
                  onChange={(e) => setRejectReason(e.target.value)}
                  className={styles.s22}
                />
                <button
                  className="btn btn-danger btn-sm"
                  onClick={handleReject}
                  disabled={busy || !rejectReason.trim()}
                >
                  Confirm Rejection
                </button>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
