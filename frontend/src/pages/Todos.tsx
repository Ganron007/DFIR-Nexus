/**
 * TODOs — investigation follow-ups (WP 4d.4 / 4j.5n), migrated to the kit
 * (WO-U8a).
 *
 * Kit: PageHeader + Panel + EmptyState + Badge + Button/Field/Select, styles in
 * a CSS module, zero inline style objects.
 * Data: two case-scoped queries. The old page re-fetched through a component
 * -local `load()` after every write, with no cache to invalidate — a write on
 * one screen left another reading stale TODOs. The mutations now invalidate the
 * list they belong to.
 *
 * A sealed case still shows its TODOs and still allows reading them; it simply
 * refuses new writes, the same rule the old page applied.
 */
import { useState } from "react";

import { useCase } from "../context/CaseContext";
import { isDone, todoId, useTodoMutations, useTodos } from "../api/queries/todos";
import {
  Badge,
  Button,
  EmptyState,
  Field,
  Input,
  PageHeader,
  Panel,
  Select,
} from "@/ui";
import type { SemanticTone } from "@/ui";
import styles from "./Page.module.css";
import pageStyles from "./Todos.module.css";

function priorityTone(priority: string | undefined): SemanticTone | undefined {
  switch ((priority || "medium").toLowerCase()) {
    case "high":
      return "sev-high";
    case "medium":
      return "sev-medium";
    case "low":
      return "sev-low";
    default:
      return undefined;
  }
}

export default function Todos() {
  const { activeCase, caseSummaries } = useCase();
  const [statusFilter, setStatusFilter] = useState("");
  const [desc, setDesc] = useState("");
  const [priority, setPriority] = useState("medium");
  const [assignee, setAssignee] = useState("");

  const { data, isLoading, error } = useTodos(activeCase, statusFilter);
  const { add, setStatus } = useTodoMutations(activeCase, statusFilter);

  const caseStatus = activeCase ? caseSummaries[activeCase]?.status || "" : "";
  const isLocked = ["sealed", "closed", "archived"].includes(caseStatus);

  const todos = data?.todos ?? [];
  const busy = add.isPending || setStatus.isPending;
  const failure =
    (error as Error | null)?.message ||
    (add.error as Error | null)?.message ||
    (setStatus.error as Error | null)?.message ||
    "";

  const submit = () => {
    if (!desc.trim() || isLocked) return;
    add.mutate(
      { description: desc.trim(), priority, assignee: assignee.trim() || undefined },
      {
        onSuccess: () => {
          setDesc("");
          setAssignee("");
        },
      },
    );
  };

  return (
    <div className={styles.page}>
      <PageHeader
        title="TODOs"
        subtitle={
          isLoading
            ? "Loading…"
            : `${todos.length} follow-up${todos.length === 1 ? "" : "s"} — persisted in the case file and audit-chained`
        }
        stageCode="N7"
        actions={
          <Field label="Status">
            {({ id }) => (
              <Select
                id={id}
                value={statusFilter}
                onChange={(event) => setStatusFilter(event.target.value)}
              >
                <option value="">All</option>
                <option value="open">Open</option>
                <option value="in_progress">In progress</option>
                <option value="completed">Completed</option>
              </Select>
            )}
          </Field>
        }
      />

      {failure ? (
        <div role="alert" className="error-banner">
          {failure}
        </div>
      ) : null}

      {isLocked ? (
        <p data-testid="todos-locked">
          This case is <strong>{caseStatus}</strong> — its TODOs stay readable,
          but new follow-ups cannot be recorded.
        </p>
      ) : null}

      {!isLocked ? (
        <Panel>
          <div className={pageStyles.addRow}>
            <Field label="Follow-up">
              {({ id }) => (
                <Input
                  id={id}
                  placeholder="Verify lateral movement to HOST2, pull SIFT twin…"
                  value={desc}
                  disabled={busy}
                  onChange={(event) => setDesc(event.target.value)}
                  onKeyDown={(event) => {
                    if (event.key === "Enter") submit();
                  }}
                />
              )}
            </Field>
            <Field label="Priority">
              {({ id }) => (
                <Select
                  id={id}
                  value={priority}
                  disabled={busy}
                  onChange={(event) => setPriority(event.target.value)}
                >
                  <option value="high">high</option>
                  <option value="medium">medium</option>
                  <option value="low">low</option>
                </Select>
              )}
            </Field>
            <Field label="Assignee">
              {({ id }) => (
                <Input
                  id={id}
                  placeholder="optional"
                  value={assignee}
                  disabled={busy}
                  onChange={(event) => setAssignee(event.target.value)}
                />
              )}
            </Field>
            <Button
              variant="primary"
              onClick={submit}
              disabled={busy || !desc.trim()}
              data-testid="todo-add"
            >
              {add.isPending ? "Adding…" : "Add TODO"}
            </Button>
          </div>
        </Panel>
      ) : null}

      {todos.length === 0 && !isLoading ? (
        <EmptyState
          title="No TODOs"
          hint="Record investigation follow-ups here — they persist in the case file and are audit-chained."
        />
      ) : todos.length > 0 ? (
        <Panel>
          <table className={styles.table}>
            <caption className="visually-hidden">Investigation follow-ups</caption>
            <thead>
              <tr>
                <th scope="col">ID</th>
                <th scope="col">Description</th>
                <th scope="col">Priority</th>
                <th scope="col">Status</th>
                <th scope="col">Assignee</th>
                <th scope="col">
                  <span className="visually-hidden">Action</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {todos.map((todo, index) => {
                const id = todoId(todo, index);
                const done = isDone(todo);
                return (
                  <tr key={id}>
                    <td className={styles.mono}>{id}</td>
                    <td className={done ? pageStyles.done : undefined}>
                      {todo.description}
                    </td>
                    <td>
                      <Badge tone={priorityTone(todo.priority)}>
                        {todo.priority || "medium"}
                      </Badge>
                    </td>
                    <td>{todo.status || "open"}</td>
                    <td>{todo.assignee || "—"}</td>
                    <td>
                      {!isLocked ? (
                        <Button
                          size="sm"
                          disabled={setStatus.isPending}
                          onClick={() =>
                            setStatus.mutate({
                              todo_id: id,
                              status: done ? "open" : "completed",
                            })
                          }
                        >
                          {done ? "Reopen" : "Complete"}
                        </Button>
                      ) : null}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </Panel>
      ) : null}
    </div>
  );
}
