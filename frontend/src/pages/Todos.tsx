/**
 * WP 4d.4: TODOs page — investigation follow-ups from the case TODO list.
 * 4j.5n: examiner add/complete via the portal (was CLI-only before).
 */
import { useEffect, useState } from "react";
import { api, type Todo } from "../api/client";
import { useCase } from "../context/CaseContext";

export default function Todos() {
  const { activeCase, caseSummaries } = useCase();
  const [todos, setTodos] = useState<Todo[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [statusFilter, setStatusFilter] = useState("");
  const [desc, setDesc] = useState("");
  const [priority, setPriority] = useState("medium");
  const [assignee, setAssignee] = useState("");
  const [adding, setAdding] = useState(false);
  const [busyId, setBusyId] = useState("");

  const caseStatus = activeCase ? caseSummaries[activeCase]?.status || "" : "";
  const isLocked = caseStatus === "sealed" || caseStatus === "closed" || caseStatus === "archived";

  const load = () => {
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
  };

  useEffect(load, [activeCase, statusFilter]);

  const add = async () => {
    if (!desc.trim()) return;
    setAdding(true);
    setError("");
    try {
      const r = await api.addTodo({
        description: desc.trim(),
        priority,
        assignee: assignee.trim() || undefined,
      });
      if (r.error) throw new Error(r.error);
      setDesc("");
      setAssignee("");
      load();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setAdding(false);
    }
  };

  const setStatus = async (t: Todo, status: string) => {
    const id = String(t.todo_id || t.id || "");
    if (!id) return;
    setBusyId(id);
    setError("");
    try {
      const r = await api.updateTodo({ todo_id: id, status });
      if (r.error) throw new Error(r.error);
      load();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusyId("");
    }
  };

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
          <option value="in_progress">In progress</option>
          <option value="completed">Completed</option>
        </select>
      </div>
      {error && <div className="error-banner">{error}</div>}

      {!isLocked && (
        <div className="card" style={{ marginBottom: 16 }}>
          <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
            <input
              placeholder="Follow-up — e.g. verify lateral movement to HOST2, pull SIFT twin"
              value={desc}
              onChange={(e) => setDesc(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && add()}
              disabled={adding}
              style={{ flex: 1, minWidth: 260 }}
            />
            <select value={priority} onChange={(e) => setPriority(e.target.value)} style={{ width: "auto" }} disabled={adding}>
              <option value="high">high</option>
              <option value="medium">medium</option>
              <option value="low">low</option>
            </select>
            <input
              placeholder="Assignee (optional)"
              value={assignee}
              onChange={(e) => setAssignee(e.target.value)}
              disabled={adding}
              style={{ width: 160 }}
            />
            <button className="btn btn-primary" onClick={add} disabled={adding || !desc.trim()}>
              {adding ? "Adding…" : "Add TODO"}
            </button>
          </div>
        </div>
      )}

      {todos.length === 0 ? (
        <div className="empty-state">
          <h3>No TODOs</h3>
          <p>Record investigation follow-ups here — they persist in the case file and are audit-chained.</p>
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
                <th></th>
              </tr>
            </thead>
            <tbody>
              {todos.map((t, i) => {
                const id = String(t.todo_id || t.id || `#${i + 1}`);
                const done = (t.status || "open") === "completed";
                return (
                  <tr key={id}>
                    <td style={{ fontFamily: "monospace", fontSize: 11 }}>{id}</td>
                    <td style={done ? { textDecoration: "line-through", opacity: 0.7 } : undefined}>{t.description}</td>
                    <td>{t.priority || "medium"}</td>
                    <td>{t.status || "open"}</td>
                    <td>{t.assignee || "—"}</td>
                    <td>
                      {!isLocked && (
                        <button
                          className="btn btn-sm"
                          onClick={() => setStatus(t, done ? "open" : "completed")}
                          disabled={busyId === id}
                        >
                          {busyId === id ? "…" : done ? "Reopen" : "Complete"}
                        </button>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
