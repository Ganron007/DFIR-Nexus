/**
 * Mode 3 board liveness — the two questions an examiner asks while a run is live:
 * how many agents are working, and what are they doing to each other.
 *
 * The board only ever held seats that had *finished*, so a run with three agents
 * in flight rendered as an empty board, and `supervisor.spawn` recorded just
 * `{"agents": 3}` with no identity. Both are now derived from the event stream.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, act } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";

const statusRunning = {
  run_id: "M3-test",
  status: "running",
  superstep: 2,
  board: 1,
  disputes: 0,
  candidates: 0,
  agents_running: 2,
  agents_active: [
    {
      agent_id: "pattern:prefetch:2",
      role: "pattern",
      family: "prefetch",
      superstep: 2,
      why: "dispute lsass.exe",
    },
    {
      agent_id: "evidence:hayabusa:2",
      role: "evidence",
      family: "hayabusa",
      superstep: 2,
      why: "highest-value family",
    },
  ],
  roles: ["evidence", "pattern"],
  skills_used: 3,
  events: 12,
};

const statusSettled = {
  run_id: "M3-test",
  status: "completed",
  superstep: 2,
  board: 4,
  disputes: 1,
  candidates: 4,
  agents_running: 0,
  agents_active: [],
  roles: ["evidence", "pattern", "correlation"],
  skills_used: 5,
  events: 40,
};

const boardPayload = {
  run_id: "M3-test",
  board: [
    {
      agent_id: "evidence:hayabusa:1",
      role: "evidence",
      family: "hayabusa",
      superstep: 1,
      claims: [
        {
          entity_type: "process",
          entity_value: "lsass.exe",
          claim_kind: "presence",
          polarity: "affirm",
          value: "registered with LSA",
          audit_ids: ["nexus-audit-1"],
        },
      ],
    },
  ],
  disputes: [],
  candidates: [],
  active: statusRunning.agents_active,
  timeline: [
    { ts: "t1", event: "supervisor.spawn", actor: "supervisor", detail: "2 seats" },
    {
      ts: "t2",
      event: "seat.started",
      actor: "agent",
      agent_id: "pattern:prefetch:2",
      detail: "pattern prefetch",
    },
    {
      ts: "t3",
      event: "board.entry",
      actor: "agent",
      agent_id: "evidence:hayabusa:1",
      detail: "evidence hayabusa",
    },
  ],
  skills_used: [
    { skill: "lsass_credential_access", version: "a1b2c3d4e5f6", role: "pattern" },
  ],
};

vi.mock("../api/client", () => ({
  ApiError: class ApiError extends Error {},
  mode2RunEventsPath: (id: string) => `/portal/api/mode2/run/events?run_id=${id}`,
  mode3RunEventsPath: (id: string) => `/portal/api/mode3/run/events?run_id=${id}`,
  api: {
    mode3RunStatus: vi.fn(),
    mode3RunBoard: vi.fn(),
    mode3RunStart: vi.fn(),
    mode3RunStop: vi.fn(),
    mode3RunStage: vi.fn(),
    mode3RunSteer: vi.fn(),
  },
}));

import { api } from "../api/client";
import MultiAgentBoard from "../components/MultiAgentBoard";

beforeEach(() => {
  vi.clearAllMocks();
  (api.mode3RunBoard as ReturnType<typeof vi.fn>).mockResolvedValue(boardPayload);
});

async function renderBoard() {
  await act(async () => {
    render(
      <MemoryRouter>
        <MultiAgentBoard />
      </MemoryRouter>,
    );
  });
}

describe("Mode 3 board liveness", () => {
  it("shows how many agents are running and each one's role", async () => {
    (api.mode3RunStatus as ReturnType<typeof vi.fn>).mockResolvedValue(statusRunning);
    await renderBoard();

    const count = await screen.findByTestId("agents-running");
    expect(count.textContent).toBe("2");
    // The live strip and the board both badge a role, so assert presence of the
    // in-flight seat specifically rather than a unique global match.
    expect(screen.getByText("PATTERN")).toBeTruthy();
    expect(screen.getAllByText("EVIDENCE").length).toBeGreaterThan(0);
    expect(screen.getByText(/dispute lsass\.exe/)).toBeTruthy();
    expect(screen.getAllByText(/working…/).length).toBe(2);
  });

  it("names the families in flight", async () => {
    (api.mode3RunStatus as ReturnType<typeof vi.fn>).mockResolvedValue(statusRunning);
    await renderBoard();
    await screen.findByTestId("agents-running");
    expect(screen.getAllByText("prefetch").length).toBeGreaterThan(0);
    expect(screen.getAllByText("hayabusa").length).toBeGreaterThan(0);
  });

  it("says nothing is in flight once the run settles", async () => {
    (api.mode3RunStatus as ReturnType<typeof vi.fn>).mockResolvedValue(statusSettled);
    await renderBoard();
    const count = await screen.findByTestId("agents-running");
    expect(count.textContent).toBe("0");
    expect(screen.getByText(/the run has settled/i)).toBeTruthy();
  });

  it("renders the interaction log from the board payload", async () => {
    (api.mode3RunStatus as ReturnType<typeof vi.fn>).mockResolvedValue(statusRunning);
    await renderBoard();
    await screen.findByTestId("agents-running");
    expect(screen.getByText(/Interaction log \(3\)/)).toBeTruthy();
    // The event type is what makes the log readable: a spawn and a seat start
    // are different things and the row must say which.
    expect(screen.getAllByText(/supervisor\.spawn/).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/seat\.started/).length).toBeGreaterThan(0);
    // spawn rows carry no agent_id, so the row reads "<event> · <actor>".
    expect(screen.getByText(/supervisor\.spawn · supervisor/)).toBeTruthy();
  });

  it("reports how many procedures the run applied", async () => {
    (api.mode3RunStatus as ReturnType<typeof vi.fn>).mockResolvedValue(statusSettled);
    await renderBoard();
    await screen.findByTestId("agents-running");
    expect(screen.getByText(/5 procedure\(s\) applied/)).toBeTruthy();
  });

  it("does not claim agents are running when the status omits the field", async () => {
    (api.mode3RunStatus as ReturnType<typeof vi.fn>).mockResolvedValue({
      run_id: "M3-test",
      status: "running",
      superstep: 1,
      board: 0,
    });
    await renderBoard();
    const count = await screen.findByTestId("agents-running");
    expect(count.textContent).toBe("0");
  });
});
