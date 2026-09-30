import type { CSSProperties } from "react";
import { SEMANTIC_TONES, type SemanticTone } from "./semantic";
import { cx } from "./cx";
import styles from "./StatusPill.module.css";

export interface StatusPillProps {
  tone: SemanticTone;
  label: string;
  /** Pulse the dot while the thing is in progress (running states). */
  pulse?: boolean;
  className?: string;
}

/** Dot + label for run / freshness / gate states. */
export function StatusPill({ tone, label, pulse = false, className }: StatusPillProps) {
  const style = {
    "--tone-accent": `var(${SEMANTIC_TONES[tone]})`,
  } as CSSProperties;
  return (
    <span className={cx(styles.pill, className)} style={style} data-tone={tone}>
      <span
        className={cx(styles.dot, pulse && styles.pulse)}
        aria-hidden="true"
      />
      {label}
    </span>
  );
}
