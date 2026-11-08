/**
 * Report domain (WO-U4): generation, viewing and steer rounds.
 */
import { downloadBlob, post, request } from "../transport";

export const reportApi = {
  reportGenerate: (params?: { profile?: string; llm?: boolean }) =>
    post<{ ok: boolean; report_path: string; findings_count: number; error?: string }>("/report/generate", params || {}),
  reportView: () =>
    request<{ ok: boolean; markdown: string; title?: string; error?: string }>("/report/view"),
  reportDownload: (params?: { format?: string; profile?: string }) => {
    const sp = new URLSearchParams();
    if (params?.format) sp.set("format", params.format);
    if (params?.profile) sp.set("profile", params.profile);
    const qs = sp.toString() ? `?${sp.toString()}` : "";
    return downloadBlob(`/report/download${qs}`, "report.md");
  },
  caseBundleExport: (params?: { since?: string }) => {
    const sp = new URLSearchParams();
    if (params?.since) sp.set("since", params.since);
    const qs = sp.toString() ? `?${sp.toString()}` : "";
    return downloadBlob(`/case/bundle${qs}`, "case-bundle.json");
  },
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
  /**
   * WO-1C item 5 — the cross-mode view inside one case. The sibling comparison
   * is gone (D5 = C: one case, three modes), so this is the single surface that
   * says what the modes agreed and contradicted on, plus the report grade.
   * Read-only and recomputable; `null` with a reason before a report exists.
   */
  reportGrade: () =>
    request<{
      case_id: string;
      grade: Record<string, unknown> | null;
      intra_case: Record<string, unknown> | null;
      reason: string | null;
    }>("/report/grade"),
};
