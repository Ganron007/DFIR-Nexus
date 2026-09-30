import type { ReactNode } from "react";
import { Badge } from "./Badge";
import styles from "./PageHeader.module.css";

export interface PageHeaderProps {
  title: string;
  subtitle?: string;
  /** Stage code rendered as a secondary badge (e.g. N4, Stage 0). */
  stageCode?: string;
  actions?: ReactNode;
}

export function PageHeader({ title, subtitle, stageCode, actions }: PageHeaderProps) {
  return (
    <header className={styles.header}>
      <div className={styles.titles}>
        <h2 className={styles.title}>
          {title}
          {stageCode ? (
            <Badge className={styles.stage}>{stageCode}</Badge>
          ) : null}
        </h2>
        {subtitle ? <p className={styles.subtitle}>{subtitle}</p> : null}
      </div>
      {actions ? <div className={styles.actions}>{actions}</div> : null}
    </header>
  );
}
