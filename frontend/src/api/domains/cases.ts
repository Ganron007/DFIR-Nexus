/**
 * Case-management domain (WO-U4). Types come from client.ts as type-only
 * imports — erased at compile time, so no runtime cycle.
 */
import { post, request } from "../transport";
import type {
  ActivateCaseResponse,
  BriefingDirection,
  BriefingResponse,
  CaseCreateResponse,
  CaseDetailsResponse,
  CaseDigestResponse,
  CaseModeResponse,
  CaseSealResponse,
  CasesResponse,
  FsListResponse,
  InterpretRoundsResponse,
  SummaryResponse,
  TransparencyResponse,
} from "../client";

export const casesApi = {
  cases: () => request<CasesResponse>("/cases"),
  activateCase: (caseId: string) =>
    post<ActivateCaseResponse>("/case/activate", { case_id: caseId }),
  deactivateCase: () => post<{ ok: boolean; active: string }>("/case/deactivate"),
  reopenCase: (caseId?: string) =>
    post<{ ok: boolean; status?: string; note?: string; reopened_from?: string; error?: string }>(
      "/case/reopen",
      { case_id: caseId },
    ),
  caseCreate: (params: {
    name: string;
    description?: string;
    examiner?: string;
    mode?: string;
    activate?: boolean;
  }) => post<CaseCreateResponse>("/case/create", params),
  caseDetails: (caseId?: string) =>
    request<CaseDetailsResponse>(`/case/details${caseId ? `?case_id=${caseId}` : ""}`),
  seedDemo: (params?: { name?: string; activate?: boolean }) =>
    post<{
      ok: boolean;
      case_id: string;
      evidence_count: number;
      findings_count: number;
      active: string;
      error?: string;
    }>("/case/seed-demo", params || {}),
  /** GATE-A — deterministic Case Digest (Mode 2/3). */
  caseDigest: () => request<CaseDigestResponse>("/case/digest"),
  /** GATE-B — interpret round log (Orient → Verify → Reconcile). */
  caseRounds: () => request<InterpretRoundsResponse>("/case/rounds"),
  caseBriefing: () => request<BriefingResponse>("/case/briefing"),
  /** Lazy LLM layer — fetched after the deterministic briefing renders. */
  caseBriefingDirections: () =>
    request<{ directions: BriefingDirection[] }>("/case/briefing/directions"),
  summary: () => request<SummaryResponse>("/summary"),
  transparency: () => request<TransparencyResponse>("/transparency"),
  fsList: (path?: string) =>
    request<FsListResponse>(`/fs/list${path ? `?path=${encodeURIComponent(path)}` : ""}`),
  setCaseMode: (mode: string, caseId?: string) =>
    post<CaseModeResponse>("/case/mode", { mode, case_id: caseId }),
  getCaseMode: (caseId?: string) =>
    request<CaseModeResponse>(`/case/mode${caseId ? `?case_id=${caseId}` : ""}`),
  /** Seal & close the active case — HMAC challenge-response, same flow as
   *  per-finding approval (`POST /portal/api/case/seal`). Lifecycle action for
   *  every mode. */
  sealCase: (params: {
    challenge_id: string;
    response: string;
    examiner?: string;
  }) => post<CaseSealResponse>("/case/seal", params),
};
