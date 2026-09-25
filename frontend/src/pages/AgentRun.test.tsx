/**
 * Mode 3 Agent Run view (M6) — live board, verdict/candidate panels, staging.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, act } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";

const statusRecord = {
  run_id: "M3-test",
  status: "running",
  stop_reason: "",
  pause_requested: false,
  question: "Trace RDP and USB",
  orders: 2,
  order_index: 1,
  followup_rounds: 1,
  results: 2,
  candidates: 1,
  gaps: 0,
  events: 3,
  verdicts: [
    { title: "RDP reconnect", class: "inferred", basis: "single family" },
  ],
  candidate_findings: [
    {
      title: "USB mass storage seen",
      observation: "TOSHIBA device recognized",
      interpretation: "removable device use",
      confidence: "LOW",
      audit_ids: ["nexus-audit-1", "nexus-audit-2"],
    },
  ],
};

vi.mock("../api/client", () => ({
  ApiError: class ApiError extends Error {},
  mode3RunEventsPath: (id: string) => `/portal/api/mode3/run/events?run_id=${id}`,
  api: {
    mode3RunStatus: vi.fn(async () => statusRecord),
    mode3RunPlan: vi.fn(async () => ({
      run_id: "M3-plan",
      question: "Trace RDP and USB",
      orders: [
        { order_id: "wo-1", role: "evidence", task: "Investigate hayabusa", family: "hayabusa" },
      ],
    })),
    mode3RunStart: vi.fn(async () => ({ run_id: "M3-test", status: "running" })),
    mode3RunPause: vi.fn(async () => ({ run_id: "M3-test", paused: true })),
    mode3RunResume: vi.fn(async () => ({ run_id: "M3-test", status: "running" })),
    mode3RunSteer: vi.fn(async () => ({ run_id: "M3-test", steering: { ts: "t", text: "x" } })),
    mode3RunStage: vi.fn(async () => ({
      run_id: "M3-test",
      staged_count: 1,
      skipped_count: 0,
      staged: [{ title: "USB mass storage seen", finding_id: "F-001", verifier_class: "inferred" }],
      skipped: [],
    })),
  },
}));

class FakeEventSource {
  static instances: FakeEventSource[] = [];
  listeners: Record<string, ((ev: MessageEvent) => void)[]> = {};
  url: string;
  constructor(url: string) {
    this.url = url;
    FakeEventSource.instances.push(this);
  }
  addEventListener(type: string, cb: (ev: MessageEvent) => void) {
    (this.listeners[type] ||= []).push(cb);
  }
  removeEventListener(type: string, cb: (ev: MessageEvent) => void) {
    this.listeners[type] = (this.listeners[type] || []).filter((f) => f !== cb);
  }
  close() {}
  emit(type: string, data: unknown) {
    for (const cb of this.listeners[type] || []) {
      cb({ data: JSON.stringify(data) } as MessageEvent);
    }
  }
}

beforeEach(() => {
  FakeEventSource.instances = [];
  (globalThis as unknown as { EventSource: unknown }).EventSource = FakeEventSource;
});

import AgentRun from "./AgentRun";

describe("AgentRun (Mode 3)", () => {
  it("renders verdicts, candidates with lineage and stages DRAFTs", async () => {
    render(
      <MemoryRouter>
        <AgentRun />
      </MemoryRouter>,
    );

    expect(await screen.findByText(/M3-test/)).toBeTruthy();
    expect(await screen.findByText("RDP reconnect")).toBeTruthy();
    expect(await screen.findByText("USB mass storage seen")).toBeTruthy();
    expect(await screen.findByText(/nexus-audit-1/)).toBeTruthy();

    const stageButton = screen.getByRole("button", { name: /Stage DRAFTs/ });
    await act(async () => {
      stageButton.click();
    });
    expect(await screen.findByText(/Staged 1 DRAFT/)).toBeTruthy();
  });

  it("streams agent events into the board and tool log", async () => {
    render(
      <MemoryRouter>
        <AgentRun />
      </MemoryRouter>,
    );
    expect(await screen.findByText(/M3-test/)).toBeTruthy();
    const source = FakeEventSource.instances[0];
    expect(source).toBeTruthy();
    expect(source.url).toContain("/mode3/run/events?run_id=M3-test");

    await act(async () => {
      source.emit("agent", {
        event_id: "e1", ts: "2026-09-25T06:00:00Z", run_id: "M3-test",
        event_type: "work_order.started", actor: "director",
        agent_id: "evidence-wo-1", detail: "Investigate hayabusa",
        data: { role: "evidence", order_id: "wo-1", family: "hayabusa",
                skills: [{ skill: "evtx-logon", version: "abc123" }],
                budget: { rounds: 5, calls: 12, seconds: 300 } },
      });
      source.emit("agent", {
        event_id: "e2", ts: "2026-09-25T06:00:05Z", run_id: "M3-test",
        event_type: "agent.round", actor: "agent",
        agent_id: "evidence-wo-1", detail: "round 2/5",
      });
      source.emit("agent", {
        event_id: "e3", ts: "2026-09-25T06:00:10Z", run_id: "M3-test",
        event_type: "tool.call", actor: "agent", agent_id: "evidence-wo-1",
        tool: "es_aggregate", why: "count event ids",
      });
    });

    expect(await screen.findByText(/evtx-logon vabc123/)).toBeTruthy();
    expect(await screen.findByText(/es_aggregate/)).toBeTruthy();
    const lane = screen.getByText(/evtx-logon vabc123/).closest(".agent-lane");
    expect(lane?.textContent).toContain("rounds 2/5");
    expect(lane?.textContent).toContain("calls 1/12");
  });

  it("previews a plan before running", async () => {
    render(
      <MemoryRouter>
        <AgentRun />
      </MemoryRouter>,
    );
    const preview = await screen.findByRole("button", { name: /Preview plan/ });
    await act(async () => {
      preview.click();
    });
    expect(await screen.findByText(/Investigate hayabusa/)).toBeTruthy();
    expect(await screen.findByText(/wo-1/)).toBeTruthy();
  });
});
