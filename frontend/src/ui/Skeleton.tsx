import { cx } from "./cx";
import styles from "./Skeleton.module.css";

export interface SkeletonProps {
  /** Number of skeleton lines; height in px each. */
  lines?: number;
  height?: number;
  className?: string;
}

/** First-paint placeholder — never a spinner-only screen. */
export function Skeleton({ lines = 3, height = 14, className }: SkeletonProps) {
  return (
    <div className={cx(styles.skeleton, className)} aria-hidden="true">
      {Array.from({ length: lines }, (_, i) => (
        <div
          key={i}
          className={styles.line}
          style={{ height }}
        />
      ))}
    </div>
  );
}
