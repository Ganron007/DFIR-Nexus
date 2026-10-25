import { describe, expect, it } from "vitest";

import { mode1Progress, mode2Progress, mode3Progress } from "./progress";
import { runModeSequence, type ModeRow } from "./sequence";

describe("analysis progress lines", () => {
  it("Mode 1: the last pipeline node and the tool lane's counters", () => {
    expect(
      mode1Progress({
        run_id: "R", case_id: "C", mode: "interpret", status: "running",
        stages: [{ stage: "load_case", status: "done" }, { tool: "evtxecmd", status: "ok" }, { stage: "interpret", status: "running" }],
        progress: { done: 3, total: 7, running: { tool: "hayabusa" } },
      }),
    ).toBe("interpret running · tools 3/7 · running hayabusa");
  });

  it("Mode 2: the work order, counts and last event; absent fields are left out, not shown as zero", () => {
    expect(
      mode2Progress({
        run_id: "M2", status: "running", orders: 7, order_index: 2, candidates: 1, events: 40,
        last_event: { event_id: "e", ts: "t", run_id: "M2", event_type: "tool.result", actor: "worker", tool: "es_search" },
      }),
    ).toBe("2/7 order(s) done · 1 candidate(s) · 40 event(s) · last: tool.result es_search");
    expect(mode2Progress({ run_id: "M2", status: "planned" })).toBe("");
  });

  it("Mode 3: superstep, agents working and the board", () => {
    expect(
      mode3Progress({ run_id: "M3", status: "running", superstep: 4, agents_running: 3, board: 12, candidates: 2, disputes: 0 }),
    ).toBe("superstep 4 · 3 agent(s) working · 12 board item(s) · 2 candidate(s)");
  });

  it("the sequence publishes every status read, so the page updates while a run runs", async () => {
    const readings = [
      { status: "running", progress: "superstep 1" },
      { status: "running", progress: "superstep 2" },
      { status: "completed", progress: "superstep 3" },
    ];
    let i = 0;
    const frames: ModeRow[][] = [];
    await runModeSequence({
      modes: ["3"],
      policy: "independent",
      adapter: {
        start: async () => ({ runId: "M3-1" }),
        status: async () => readings[Math.min(i++, readings.length - 1)],
      },
      onRows: (rows) => frames.push(rows),
      sleep: async () => {},
      pollMs: 0,
    });
    const seen = frames.map((rows) => rows[0].progress).filter(Boolean);
    expect(seen).toContain("superstep 1");
    expect(seen).toContain("superstep 2");
    expect(frames.at(-1)?.[0]).toMatchObject({ state: "done", status: "completed", progress: "superstep 3" });
  });
});
