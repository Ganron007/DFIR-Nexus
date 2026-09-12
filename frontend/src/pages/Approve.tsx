import { useEffect, useState } from "react";
import { api, type Finding } from "../api/client";
import { computeApprovalResponse } from "../lib/crypto";
import { useCase } from "../context/CaseContext";

export default function Approve() {
  const { activeCase } = useCase();
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

  const handleApprove = async () => {
    setError("");
    setResult("");
    if (selected.size === 0) {
      setError("Select at least one finding to approve");
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
      });

      if (r.errors.length > 0) {
        setError(`${r.errors.length} error(s): ${r.errors.map((e) => e.error).join("; ")}`);
      }
      if (r.approved.length > 0) {
        setResult(`✓ Successfully approved ${r.approved.length} finding(s): ${r.approved.join(", ")}`);
        setPassword("");
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
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 16 }}>
        <h2>Approval Desk (N6)</h2>
        {findings.length > 0 && (
          <div style={{ display: "flex", gap: 8 }}>
            <button className="btn btn-sm" onClick={selectAll}>Select All</button>
            <button className="btn btn-sm" onClick={clearSelection}>Clear</button>
          </div>
        )}
      </div>

      {error && <div className="error-banner">{error}</div>}
      {result && (
        <div style={{ background: "rgba(63,185,80,0.1)", border: "1px solid var(--success)", borderRadius: 6, padding: 10, marginBottom: 16, color: "var(--success)" }}>
          {result}
        </div>
      )}

      <div className="card" style={{ marginBottom: 16 }}>
        <div className="card-header">
          <span className="card-title">DRAFT Findings ({findings.length})</span>
          <span style={{ fontSize: 12, color: "var(--text-muted)" }}>{selected.size} selected</span>
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
                <th style={{ width: 30 }}></th>
                <th>ID</th>
                <th>Title</th>
                <th>Confidence</th>
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
                      style={{ width: "auto", cursor: "pointer" }}
                    />
                  </td>
                  <td style={{ fontFamily: "monospace", fontSize: 11 }}>{f.id}</td>
                  <td>
                    <strong>{f.title}</strong>
                    {f.observation && (
                      <div style={{ fontSize: 12, color: "var(--text-secondary)", marginTop: 2 }}>
                        {f.observation.slice(0, 100)}...
                      </div>
                    )}
                  </td>
                  <td><span className={`badge badge-${f.confidence.toLowerCase()}`}>{f.confidence}</span></td>
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
          <div style={{ maxWidth: 440, display: "flex", flexDirection: "column", gap: 12 }}>
            <p style={{ fontSize: 13, color: "var(--text-secondary)", margin: 0 }}>
              Approving signs a PBKDF2-HMAC-SHA256 entry to the immutable ledger.
              Enter the <strong>examiner approval password</strong>
              {examinerIdentity ? ` for identity '${examinerIdentity}'` : ""} — the one
              set with <code>nexus config --setup-password</code>. It never leaves this
              browser: Web Crypto derives the signature locally, and the server sees
              only an HMAC of a one-time challenge.
            </p>

            {passwordConfigured === false && (
              <div className="error-banner" style={{ margin: 0 }}>
                No approval password is configured
                {examinerIdentity ? ` for '${examinerIdentity}'` : ""} — approving will
                fail. Set one first: <code>{setupHint || "nexus config --setup-password"}</code>
              </div>
            )}

            <div>
              <label style={{ fontSize: 12, color: "var(--text-muted)", display: "block", marginBottom: 4 }}>
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
              <label style={{ fontSize: 12, color: "var(--text-muted)", display: "block", marginBottom: 4 }}>
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

            {statusMsg && (
              <div style={{ fontSize: 12, color: "var(--accent)" }}>
                ⚡ {statusMsg}
              </div>
            )}

            <div style={{ display: "flex", gap: 10, marginTop: 4 }}>
              <button
                className="btn btn-primary"
                onClick={handleApprove}
                disabled={busy || selected.size === 0}
                title={!password ? "Enter the examiner approval password first — click for details" : undefined}
                style={{ flex: 1 }}
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
              <div style={{ marginTop: 8, padding: 12, border: "1px solid var(--border)", borderRadius: 6, background: "var(--bg-secondary)" }}>
                <label style={{ fontSize: 12, color: "var(--danger)", display: "block", marginBottom: 4, fontWeight: 600 }}>
                  Reason for Rejection (required by FD-001)
                </label>
                <input
                  placeholder="e.g. Legitimate administrative activity, baseline software"
                  value={rejectReason}
                  onChange={(e) => setRejectReason(e.target.value)}
                  style={{ marginBottom: 8 }}
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
