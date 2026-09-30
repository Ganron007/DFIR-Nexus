import type { CSSProperties, ReactNode } from "react";
import { SEMANTIC_TONES, type SemanticTone } from "./semantic";
import { cx } from "./cx";
import styles from "./Badge.module.css";

export interface BadgeProps {
  /** Semantic tone; omit for the neutral badge. */
  tone?: SemanticTone;
  children: ReactNode;
  className?: string;
}

/**
 * Semantic badge. The accent is bound through the tone registry (semantic.ts)
 * — the only value this component injects is a token reference, never a raw
 * colour (UI-FOUNDATION-DESIGN §2.3).
 */
export function Badge({ tone, children, className }: BadgeProps) {
  const style = (
    tone ? { "--tone-accent": `var(${SEMANTIC_TONES[tone]})` } : undefined
  ) as CSSProperties | undefined;
  return (
    <span className={cx(styles.badge, className)} style={style} data-tone={tone}>
      {children}
    </span>
  );
}
