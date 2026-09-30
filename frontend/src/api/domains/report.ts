/**
 * Report domain (WO-U4): generation, viewing and steer rounds.
 */
import { post, request } from "../transport";

export const reportApi = {
  reportGenerate: (params?: { profile?: string; llm?: boolean }) =>
    post<{ ok: boolean; report_path: string; findings_count: number; error?: string }>("/report/generate", params || {}),
  reportView: () =>
    request<{ ok: boolean; markdown: string; title?: string; error?: string }>("/report/view"),
  reportSteer: (params: { instruction: string; finding_id?: string; llm?: boolean }) =>
    post<{
      ok: boolean;
      report_path: string;
      findings_count: number;
      round: number;
      instructions_applied: number;
      steer_preview?: string;
      report_sha256?: string;
      snapshot_path?: string;
      error?: string;
    }>("/report/steer", params),
  reportRounds: () =>
    request<{
      rounds: Array<{
        round: number;
        ts: string;
        instruction: string;
        finding_id?: string;
        model?: string;
        findings_hash?: string;
        report_sha256?: string;
        snapshot_path?: string;
        previous_report_sha256?: string;
      }>;
    }>("/report/rounds"),
};
