/**
 * System domain (WO-U4): backend/ES/SIFT health polling and the setup tasks.
 */
import { post, request } from "../transport";
import type {
  SetupEnvResponse,
  SetupStatusResponse,
  SetupTask,
  SystemHealthResponse,
} from "../client";
import type { CaseStatusResponse } from "../caseStatus";

export const systemApi = {
  systemHealth: () => request<SystemHealthResponse>("/system/health"),
  /** WO-U3: the single case status source (stepper, gate banner, headers). */
  caseStatus: (caseId: string) =>
    request<CaseStatusResponse>(`/case/status?case_id=${encodeURIComponent(caseId)}`),
  setupEnv: (env: Record<string, string>) =>
    post<SetupEnvResponse>("/setup/env", env),
  setupRag: () => post<{ status?: string; task?: SetupTask; error?: string }>("/setup/rag", {}),
  setupStatus: () => request<SetupStatusResponse>("/setup/status"),
};
