import type { ReactNode } from "react";
import { cx } from "./cx";
import styles from "./EmptyState.module.css";

export interface EmptyStateProps {
  title: string;
  hint?: ReactNode;
  icon?: ReactNode;
  action?: ReactNode;
  /** error renders the title in the danger accent (query failures). */
  tone?: "default" | "error";
  className?: string;
}

/** The only zero-state. Every empty list region uses it, with the action that fixes the situation. */
export function EmptyState({
  title,
  hint,
  icon,
  action,
  tone = "default",
  className,
}: EmptyStateProps) {
  return (
    <div
      className={cx(styles.empty, tone === "error" && styles.error, className)}
      role="status"
    >
      {icon ? <div className={styles.icon}>{icon}</div> : null}
      <p className={styles.title}>{title}</p>
      {hint ? <p className={styles.hint}>{hint}</p> : null}
      {action ? <div className={styles.action}>{action}</div> : null}
    </div>
  );
}
