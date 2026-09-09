/**
 * WP 4d.4: TODOs page — investigation follow-ups from the case TODO list.
 */
import { useEffect, useState } from "react";
import { api, type Todo } from "../api/client";
import { useCase } from "../context/CaseContext";

export default function Todos() {
  const { activeCase } = useCase();
  const [todos, setTodos] = useState<Todo[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [statusFilter, setStatusFilter] = useState("");

  useEffect(() => {
    if (!activeCase) {
      setTodos([]);
      setLoading(false);
      return;
    }
    setLoading(true);
    setError("");
    api.todos(statusFilter || undefined)
      .then((r) => setTodos(r.todos))
      .catch((e) => setError((e as Error).message))
      .finally(() => setLoading(false));
  }, [activeCase, statusFilter]);

  if (loading) return <div className="loading">Loading TODOs...</div>;

  return (
    <div>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 16 }}>
        <h2>TODOs ({todos.length})</h2>
        <select
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}
          style={{ width: "auto" }}
        >
          <option value="">All</option>
          <option value="open">Open</option>
          <option value="done">Done</option>
        </select>
      </div>
      {error && <div className="error-banner">{error}</div>}
      {todos.length === 0 ? (
        <div className="empty-state">
          <h3>No TODOs</h3>
          <p>TODOs are created during the investigation (e.g. by Mode 3 agent runs or examiner notes).</p>
        </div>
      ) : (
        <div className="card">
          <table>
            <thead>
              <tr>
                <th>ID</th>
                <th>Description</th>
                <th>Priority</th>
                <th>Status</th>
                <th>Assignee</th>
              </tr>
            </thead>
            <tbody>
              {todos.map((t, i) => (
                <tr key={i}>
                  <td style={{ fontFamily: "monospace", fontSize: 11 }}>{String(t.todo_id || t.id || `#${i + 1}`)}</td>
                  <td>{t.description}</td>
                  <td>{t.priority || "medium"}</td>
                  <td>{t.status || "open"}</td>
                  <td>{t.assignee || "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
