import { useEffect, useState } from "react";
import { api, type Finding, type ChallengeResponse } from "../api/client";

export default function Approve() {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [challenge, setChallenge] = useState<ChallengeResponse | null>(null);
  const [response, setResponse] = useState("");
  const [examiner, setExaminer] = useState("");
  const [result, setResult] = useState<string>("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);

  const load = () => {
    setLoading(true);
    api.findings("DRAFT")
      .then((r) => setFindings(r.findings))
      .catch((e) => setError((e as Error).message))
      .finally(() => setLoading(false));
  };

  useEffect(() => load(), []);

  const toggle = (id: string) => {
    const next = new Set(selected);
    next.has(id) ? next.delete(id) : next.add(id);
    setSelected(next);
  };

  const getChallenge = async () => {
    setError("");
    try {
      const ch = await api.getChallenge();
      setChallenge(ch);
    } catch (e) {
      setError((e as Error).message);
    }
  };

  const approve = async () => {
    setError("");
    setResult("");
    if (!challenge) {
      setError("Get a challenge first");
      return;
    }
    if (selected.size === 0) {
      setError("Select at least one finding");
      return;
    }
    if (!examiner.trim()) {
      setError("Examiner name is required");
      return;
    }
    if (!response.trim()) {
      setError("HMAC response is required");
      return;
    }
    try {
      const r = await api.commit({
        finding_ids: [...selected],
        challenge_id: challenge.challenge_id,
        response,
        examiner,
      });
      if (r.errors.length > 0) {
        setError(`${r.errors.length} error(s): ${r.errors.map((e) => e.error).join("; ")}`);
      }
      if (r.approved.length > 0) {
        setResult(`Approved ${r.approved.length} finding(s): ${r.approved.join(", ")}`);
        setSelected(new Set());
        setChallenge(null);
        setResponse("");
        load();
      }
    } catch (e) {
      setError((e as Error).message);
    }
  };

  if (loading) return <div className="loading">Loading DRAFT findings...</div>;

  return (
    <div>
      <h2 style={{ marginBottom: 16 }}>Approval Desk</h2>
      {error && <div className="error-banner">{error}</div>}
      {result && (
        <div style={{ background: "rgba(63,185,80,0.1)", border: "1px solid var(--success)", borderRadius: 6, padding: 10, marginBottom: 16, color: "var(--success)" }}>
          {result}
        </div>
      )}
      <div className="card">
        <div className="card-header">
          <span className="card-title">DRAFT Findings ({findings.length})</span>
          <span style={{ fontSize: 12, color: "var(--text-muted)" }}>{selected.size} selected</span>
        </div>
        {findings.length === 0 ? (
          <div className="empty-state">
            <h3>No DRAFT findings</h3>
            <p>Findings awaiting approval will appear here.</p>
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
                      style={{ width: "auto" }}
                    />
                  </td>
                  <td style={{ fontFamily: "monospace", fontSize: 11 }}>{f.id}</td>
                  <td>{f.title}</td>
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
            <span className="card-title">HMAC Challenge-Response</span>
          </div>
          <div style={{ display: "flex", flexDirection: "column", gap: 10, maxWidth: 400 }}>
            <input
              placeholder="Examiner name"
              value={examiner}
              onChange={(e) => setExaminer(e.target.value)}
            />
            {!challenge ? (
              <button className="btn btn-primary" onClick={getChallenge}>
                Get Challenge
              </button>
            ) : (
              <>
                <div style={{ fontSize: 12, color: "var(--text-muted)" }}>
                  Nonce: <code>{challenge.nonce.slice(0, 32)}...</code>
                  <br />
                  Salt: <code>{challenge.salt}</code>
                  <br />
                  Iterations: {challenge.iterations}
                </div>
                <input
                  placeholder="HMAC response (hex)"
                  value={response}
                  onChange={(e) => setResponse(e.target.value)}
                  style={{ fontFamily: "monospace" }}
                />
                <button className="btn btn-primary" onClick={approve}>
                  Approve {selected.size} Finding(s)
                </button>
              </>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
