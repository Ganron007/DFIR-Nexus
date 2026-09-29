/**
 * The evidence gate is the hard rule: unprocessed evidence refuses analysis.
 * The banner makes that refusal visible on every cockpit page instead of
 * surfacing as an unexplained 409 when a mode run is attempted.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, act } from "@testing-library/react";

vi.mock("../context/CaseContext", () => ({
  useCase: () => ({ activeCase: "CASE-TEST" }),
}));

vi.mock("../api/client", () => ({
  api: { summary: vi.fn() },
}));

import { api } from "../api/client";
import LaneGateBanner from "./LaneGateBanner";

const counts = {
  findings: { total: 0, draft: 0, approved: 0, rejected: 0 },
  timeline: 0,
  evidence: 2,
  todos: { total: 0, open: 0 },
};

const stages = [
  { stage: "N1", status: "done", detail: "2 evidence item(s)" },
  { stage: "N2", status: "blocked", detail: "run RUN-1: 1 unprocessed" },
  { stage: "N3", status: "done", detail: "1014547 indexed doc(s)" },
  { stage: "N4", status: "pending", detail: "no scan output yet" },
  { stage: "N5", status: "pending", detail: "no mode run" },
  { stage: "N6", status: "pending", detail: "" },
  { stage: "N7", status: "pending", detail: "" },
  { stage: "N8", status: "pending", detail: "" },
];

async function renderBanner() {
  await act(async () => {
    render(<LaneGateBanner />);
  });
}

beforeEach(() => {
  vi.clearAllMocks();
});

describe("evidence gate banner", () => {
  it("shows the blocked artifacts, the refusal and how to clear it", async () => {
    (api.summary as ReturnType<typeof vi.fn>).mockResolvedValue({
      ...counts,
      lane_gate: {
        status: "blocked",
        blocked_count: 1,
        run_id: "RUN-1",
        unprocessed: [
          { tool: "mftecmd", purpose: "NTFS metadata ($I30)", reason: "Command timed out after 240s" },
        ],
      },
      n_stages: stages,
    });
    await renderBanner();
    expect(await screen.findByText(/EVIDENCE GATE BLOCKED/)).toBeTruthy();
    const item = screen.getAllByTestId("lane-gate-item")[0];
    expect(item.textContent).toContain("mftecmd");
    expect(item.textContent).toContain("Command timed out");
    expect(screen.getByText(/nexus lane skip/)).toBeTruthy();
    expect(screen.getByTestId("nstage-N2").textContent).toContain("blocked");
  });

  it("renders a slim clear line with the recorded examiner skips", async () => {
    (api.summary as ReturnType<typeof vi.fn>).mockResolvedValue({
      ...counts,
      lane_gate: {
        status: "clear",
        blocked_count: 0,
        run_id: "RUN-2",
        unprocessed: [],
        examiner_skips: [{ examiner: "gate_bot", reason: "accepted limitation" }],
      },
      n_stages: stages,
    });
    await renderBanner();
    expect(await screen.findByText(/Evidence gate: clear/)).toBeTruthy();
    expect(screen.getByText(/1 examiner skip/)).toBeTruthy();
  });

  it("is honest when no tool-lane pass has run yet", async () => {
    (api.summary as ReturnType<typeof vi.fn>).mockResolvedValue({ ...counts, n_stages: stages });
    await renderBanner();
    expect(await screen.findByText(/no tool-lane pass recorded yet/)).toBeTruthy();
  });

  it("shows all eight N stages with their state", async () => {
    (api.summary as ReturnType<typeof vi.fn>).mockResolvedValue({
      ...counts,
      lane_gate: { status: "clear" },
      n_stages: stages,
    });
    await renderBanner();
    for (const s of stages) {
      expect(screen.getByTestId(`nstage-${s.stage}`)).toBeTruthy();
    }
  });
});
