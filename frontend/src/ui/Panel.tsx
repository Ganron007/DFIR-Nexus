import type { ReactNode } from "react";
import { cx } from "./cx";
import styles from "./Panel.module.css";

export interface PanelProps {
  title?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
}

/** The only card primitive. */
export function Panel({ title, actions, children, className }: PanelProps) {
  return (
    <section className={cx(styles.panel, className)}>
      {title || actions ? (
        <header className={styles.header}>
          {title ? <h3 className={styles.title}>{title}</h3> : null}
          {actions ? <div className={styles.actions}>{actions}</div> : null}
        </header>
      ) : null}
      <div className={styles.body}>{children}</div>
    </section>
  );
}
