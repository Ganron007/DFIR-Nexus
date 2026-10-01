import type { Finding } from "../api/client";
import type { SemanticTone } from "@/ui";

export function originMark(finding: Pick<Finding, "examiner_selected" | "provenance">): {
  label: string;
  tone: SemanticTone;
} {
  const origin = (finding.provenance?.origin || "").toLowerCase();
  if (origin === "agent") return { label: "agent", tone: "origin-agent" };
  if (origin === "llm" || finding.examiner_selected === false) {
    return { label: "LLM", tone: "origin-llm" };
  }
  return { label: "examiner", tone: "origin-examiner" };
}

export function verifierMark(finding: Pick<Finding, "verifier">): {
  label: string;
  tone: SemanticTone;
} {
  const verdict = (finding.verifier?.verdict || "").toUpperCase();
  if (verdict === "CONFIRMED") return { label: "CONFIRMED", tone: "verifier-confirmed" };
  if (verdict === "INFERRED") return { label: "INFERRED", tone: "verifier-inferred" };
  if (verdict === "REFUTED") return { label: "REFUTED", tone: "verifier-refuted" };
  if (verdict === "SKIPPED") return { label: "not auto-checked", tone: "verifier-unverified" };
  return { label: "unverified", tone: "verifier-unverified" };
}
