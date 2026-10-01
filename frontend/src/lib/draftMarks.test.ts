import { describe, expect, it } from "vitest";
import { originMark, verifierMark } from "./draftMarks";

describe("draft marks", () => {
  it("labels a model draft and a confirmed re-check", () => {
    const origin = originMark({
      examiner_selected: false,
      provenance: { origin: "llm", mode: 1, path: "full_run" },
    });
    const verifier = verifierMark({ verifier: { verdict: "CONFIRMED", reason: "rows" } });
    expect(origin).toEqual({ label: "LLM", tone: "origin-llm" });
    expect(verifier).toEqual({ label: "CONFIRMED", tone: "verifier-confirmed" });
  });

  it("does not treat an examiner draft as a model claim", () => {
    expect(originMark({ examiner_selected: true }).label).toBe("examiner");
    expect(verifierMark({ verifier: { verdict: "skipped" } }).label).toBe("not auto-checked");
  });
});