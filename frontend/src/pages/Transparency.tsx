import { useEffect, useState } from "react";
import { api } from "../api/client";

interface TransparencyResult {
  valid: boolean;
  entries: number;
  error?: string;
  tampered?: number | string;
  expected?: string;
  actual?: string;
  expected_previous?: string;
  actual_previous?: string;
}

export default function Transparency() {
  const [result, setResult] = useState<TransparencyResult | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    api.transparency()
      .then((r) => setResult(r as unknown as TransparencyResult))
      .catch((e) => setError((e as Error).message))
      .finally(() => setLoading(false));
  }, []);

  if (loading) return <div className="loading">Loading transparency log...</div>;

  return (
    <div>
      <h2 style={{ marginBottom: 16 }}>Transparency Log</h2>
      {error && <div className="error-banner">{error}</div>}
      <div className="card">
        <div className="card-header">
          <span className="card-title">HMAC Audit Chain Verification</span>
        </div>
        {!result ? (
          <div className="empty-state">
            <p>No transparency data available.</p>
          </div>
        ) : (
          <div style={{ padding: 16 }}>
            <div style={{
              display: "inline-flex",
              alignItems: "center",
              gap: 8,
              padding: "8px 16px",
              borderRadius: 6,
              marginBottom: 16,
              background: result.valid ? "rgba(63,185,80,0.1)" : "rgba(248,81,73,0.1)",
              border: `1px solid ${result.valid ? "var(--success)" : "var(--danger)"}`,
            }}>
              <span style={{ fontSize: 20 }}>
                {result.valid ? "✓" : "✗"}
              </span>
              <span style={{ fontWeight: 600, color: result.valid ? "var(--success)" : "var(--danger)" }}>
                {result.valid ? "Chain Valid" : "Chain Tampered"}
              </span>
            </div>
            <table>
              <tbody>
                <tr>
                  <td style={{ color: "var(--text-muted)", width: 200 }}>Total entries</td>
                  <td>{result.entries}</td>
                </tr>
                {result.error && (
                  <tr>
                    <td style={{ color: "var(--text-muted)" }}>Error</td>
                    <td style={{ color: "var(--danger)" }}>{result.error}</td>
                  </tr>
                )}
                {result.tampered !== undefined && (
                  <tr>
                    <td style={{ color: "var(--text-muted)" }}>Tampered at index</td>
                    <td style={{ color: "var(--danger)" }}>{result.tampered}</td>
                  </tr>
                )}
                {result.expected && (
                  <tr>
                    <td style={{ color: "var(--text-muted)" }}>Expected hash</td>
                    <td style={{ fontFamily: "monospace", fontSize: 11 }}>{result.expected.slice(0, 32)}...</td>
                  </tr>
                )}
                {result.actual && (
                  <tr>
                    <td style={{ color: "var(--text-muted)" }}>Actual hash</td>
                    <td style={{ fontFamily: "monospace", fontSize: 11, color: "var(--danger)" }}>{result.actual.slice(0, 32)}...</td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
