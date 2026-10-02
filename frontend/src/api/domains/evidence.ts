/**
 * Evidence & intake domain (WO-U4): registered evidence, IOCs, TODOs, SIFT
 * and later-log ingest.
 */
import { post, request } from "../transport";
import type {
  EvidenceResponse,
  IocsResponse,
  TodosResponse,
} from "../client";

export const evidenceApi = {
  registerEvidence: (path: string, caseId?: string, description?: string) =>
    post<{
      ok: boolean;
      case_id?: string;
      sha256?: string;
      files?: number;
      total_bytes?: number;
      error?: string;
    }>("/evidence", { path, case_id: caseId, description }),
  evidence: () => request<EvidenceResponse>("/evidence"),
  pairEvidence: (proposal: {
    raw_name: string;
    output_name: string;
    output_sha256: string;
  }) => post<{ status?: string; error?: string }>("/evidence/pair", proposal),
  iocs: () => request<IocsResponse>("/iocs"),
  todos: (status?: string) =>
    request<TodosResponse>(`/todos${status ? `?status=${status}` : ""}`),
  addTodo: (params: {
    description: string;
    assignee?: string;
    priority?: string;
    related_findings?: string[];
  }) => post<{ status: string; todo_id?: string; error?: string }>("/todos", params),
  updateTodo: (params: {
    todo_id: string;
    status?: string;
    note?: string;
    assignee?: string;
    priority?: string;
  }) => post<{ status: string; todo_id?: string; error?: string }>("/todos/update", params),
  evidenceVerify: () =>
    post<{ ok: boolean; results: Array<{ name: string; file_path: string; valid: boolean; error?: string }> }>("/evidence/verify", {}),
  siftSelect: (required: boolean, caseId?: string) =>
    post<{ ok?: boolean; required?: boolean; reachable?: boolean; message?: string; error?: string }>(
      "/sift/select",
      { required, case_id: caseId },
    ),
  siftIngest: (path: string, family?: string, caseId?: string) =>
    post<{ ok?: boolean; staged?: string[]; index?: string[]; error?: string }>(
      "/sift/ingest",
      { path, family: family || "", case_id: caseId },
    ),
  ingest: (path: string, source?: string, caseId?: string) =>
    post<{ ok?: boolean; result?: Record<string, unknown>; index?: string[]; error?: string }>(
      "/ingest",
      { path, source: source || "", case_id: caseId },
    ),
};
