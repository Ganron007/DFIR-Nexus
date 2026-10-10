import { describe, expect, it } from "vitest";

import { runModeSequence, type AnalysisMode, type ContextPolicy, type ModeRow, type ModeRunAdapter } from "./sequence";

interface Script {
  /** Per mode: the start outcome. A string is the run id; an Error is a refusal. */
  starts?: Partial<Record<AnalysisMode, string | Error>>;
  /** Per mode: the status words returned in order; the last one repeats. */
  statuses?: Partial<Record<AnalysisMode, string[]>>;
}

function fakeAdapter(script: Script) {
  const calls: string[] = [];
  const policies: ContextPolicy[] = [];
  const cursor: Partial<Record<AnalysisMode, number>> = {};
  const adapter: ModeRunAdapter = {
    async start(mode, policy) {
      calls.push(`start:${mode}`);
      policies.push(policy);
      const outcome = script.starts?.[mode] ?? `run-${mode}`;
      if (outcome instanceof Error) throw outcome;
      return { runId: outcome };
    },
    async status(mode) {
      calls.push(`status:${mode}`);
      const words = script.statuses?.[mode] ?? [mode === "1" ? "complete" : "completed"];
      const i = cursor[mode] ?? 0;
      cursor[mode] = i + 1;
      return words[Math.min(i, words.length - 1)];
    },
  };
  return { adapter, calls, policies };
}

const noSleep = async () => {};

async function run(modes: AnalysisMode[], script: Script, policy: ContextPolicy = "independent") {
  const { adapter, calls, policies } = fakeAdapter(script);
  const frames: ModeRow[][] = [];
  const rows = await runModeSequence({
    modes,
    policy,
    adapter,
    onRows: (r) => frames.push(r),
    sleep: noSleep,
    pollMs: 0,
  });
  return { rows, calls, policies, frames };
}

describe("runModeSequence", () => {
  it("runs the chosen modes in order 1 -> 2 -> 3, whatever order they were picked in", async () => {
    const { rows, calls } = await run(["3", "1"], {});
    expect(rows.map((r) => r.mode)).toEqual(["1", "3"]);
    expect(calls.filter((c) => c.startsWith("start:"))).toEqual(["start:1", "start:3"]);
    expect(rows.every((r) => r.state === "done")).toBe(true);
  });

  it("starts a later mode only after the earlier run reached its own terminal status", async () => {
    const { calls } = await run(["1", "2"], {
      statuses: { "1": ["running", "running", "complete"], "2": ["completed"] },
    });
    const firstStart2 = calls.indexOf("start:2");
    const lastStatus1 = calls.lastIndexOf("status:1");
    expect(firstStart2).toBeGreaterThan(lastStatus1);
  });

  it("a refused start stops the sequence and says why; later modes are not started", async () => {
    const { rows, calls } = await run(["1", "2", "3"], {
      starts: { "1": new Error("no completed tools run to interpret") },
    });
    expect(rows[0]).toMatchObject({ mode: "1", state: "refused", message: "no completed tools run to interpret" });
    expect(rows[1].state).toBe("waiting");
    expect(rows[1].message).toContain("did not complete");
    expect(calls).not.toContain("start:2");
    expect(calls).not.toContain("start:3");
  });

  it("a run that ends in a failure status stops the sequence", async () => {
    const { rows, calls } = await run(["1", "2"], { statuses: { "1": ["error"] } });
    expect(rows[0]).toMatchObject({ state: "failed", status: "error" });
    expect(calls).not.toContain("start:2");
  });

  it("a stopped Mode 2 run is a failed row, not a completed one", async () => {
    const { rows } = await run(["2"], { statuses: { "2": ["running", "stopped"] } });
    expect(rows[0]).toMatchObject({ state: "failed", status: "stopped" });
  });

  it("the context policy reaches every mode's start", async () => {
    const { policies } = await run(["1", "2", "3"], {}, "informed");
    expect(policies).toEqual(["informed", "informed", "informed"]);
  });

  it("cancelling leaves the current run on the server and starts nothing more", async () => {
    const controller = new AbortController();
    const { adapter, calls } = fakeAdapter({ statuses: { "1": ["running", "running"] } });
    const rows = await runModeSequence({
      modes: ["1", "2"],
      policy: "independent",
      adapter,
      onRows: () => {},
      sleep: async () => controller.abort(),
      pollMs: 0,
      signal: controller.signal,
    });
    expect(rows[0].state).toBe("left-running");
    expect(rows[0].message).toContain("keeps going on the server");
    expect(calls).not.toContain("start:2");
  });

  it("reports every change to the rows, so the page can show each step as it happens", async () => {
    const { frames } = await run(["1"], {});
    expect(frames.length).toBeGreaterThan(2);
    expect(frames[0][0].state).toBe("waiting");
    expect(frames[frames.length - 1][0].state).toBe("done");
  });
});
