/*
 * Semantic tone registry (WO-U2; spec: UI-FOUNDATION-DESIGN.md §2.3).
 * One meaning, one token: severity / verdicts / origin / mode / seal / run /
 * freshness map to CSS custom properties in tokens.css. Badge, StatusPill and
 * report surfaces all render through these names so a value can never drift.
 */

export const SEMANTIC_TONES = {
  // Severity
  "sev-critical": "--sev-critical",
  "sev-high": "--sev-high",
  "sev-medium": "--sev-medium",
  "sev-low": "--sev-low",
  "sev-info": "--sev-info",
  // L1 claim verdicts
  "l1-proven": "--l1-proven",
  "l1-unsupported": "--l1-unsupported",
  "l1-unverifiable": "--l1-unverifiable",
  "l1-contradicted": "--l1-contradicted",
  // Verifier verdicts
  "verifier-confirmed": "--verifier-confirmed",
  "verifier-inferred": "--verifier-inferred",
  "verifier-refuted": "--verifier-refuted",
  "verifier-unverified": "--verifier-unverified",
  // Finding origin
  "origin-examiner": "--origin-examiner",
  "origin-llm": "--origin-llm",
  "origin-agent": "--origin-agent",
  // Modes
  "mode-1": "--mode-1",
  "mode-2": "--mode-2",
  "mode-3": "--mode-3",
  // Seal state
  "seal-verified": "--seal-verified",
  "seal-absent": "--seal-absent",
  "seal-broken": "--seal-broken",
  // Run states
  "run-running": "--run-running",
  "run-complete": "--run-complete",
  "run-failed": "--run-failed",
  "run-paused": "--run-paused",
  "run-stopped": "--run-stopped",
  // Evidence freshness
  "fresh-ok": "--fresh-ok",
  "fresh-stale": "--fresh-stale",
  "fresh-modified": "--fresh-modified",
} as const;

export type SemanticTone = keyof typeof SEMANTIC_TONES;

export const isSemanticTone = (value: string): value is SemanticTone =>
  Object.prototype.hasOwnProperty.call(SEMANTIC_TONES, value);

/** CSS var reference for a tone, e.g. `var(--l1-proven)`. */
export const toneVar = (tone: SemanticTone): string =>
  `var(${SEMANTIC_TONES[tone]})`;
