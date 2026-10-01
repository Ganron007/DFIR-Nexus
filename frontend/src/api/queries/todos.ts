/**
 * TODO queries (WO-U8a / WP 14.8, on the U4 hooks).
 *
 * Two reads and two writes, all keyed by case: the list, and the mutations
 * that change it. The old page re-fetched by hand after every write through a
 * component-local `load()`, with no cache to invalidate, so a write on one
 * screen could leave another reading stale TODOs.
 */
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { api, type Todo } from "../client";
import { caseKey } from "./keys";

export function useTodos(caseId: string | null | undefined, status?: string) {
  return useQuery<{ todos: Todo[] }>({
    queryKey: caseKey(caseId, "todos", status ?? "all"),
    enabled: Boolean(caseId),
    staleTime: 10_000,
    queryFn: () => api.todos(status || undefined),
  });
}

/** Add or complete a TODO, then refresh the list it belongs to. */
export function useTodoMutations(caseId: string | null | undefined, status?: string) {
  const queryClient = useQueryClient();
  const key = caseKey(caseId, "todos", status ?? "all");
  const refresh = () => queryClient.invalidateQueries({ queryKey: key });

  const add = useMutation({
    mutationFn: async (input: {
      description: string;
      priority: string;
      assignee?: string;
    }) => {
      const response = await api.addTodo(input);
      // the endpoint answers 200 with an error body rather than failing
      if (response?.error) throw new Error(response.error);
      return response;
    },
    onSuccess: refresh,
  });

  const setStatus = useMutation({
    mutationFn: async (input: { todo_id: string; status: string }) => {
      const response = await api.updateTodo(input);
      if (response?.error) throw new Error(response.error);
      return response;
    },
    onSuccess: refresh,
  });

  return { add, setStatus };
}

export function todoId(todo: Todo, index: number): string {
  return String(todo.todo_id || todo.id || `#${index + 1}`);
}

export function isDone(todo: Todo): boolean {
  return (todo.status || "open") === "completed";
}
