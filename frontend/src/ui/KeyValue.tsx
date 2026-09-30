import type { ReactNode } from "react";
import { cx } from "./cx";
import styles from "./KeyValue.module.css";

export interface KeyValueItem {
  label: string;
  value: ReactNode;
  /** Render the value in the mono font (hashes, paths, ids). */
  mono?: boolean;
}

/** Definition list for detail drawers. */
export function KeyValue({ items, className }: { items: KeyValueItem[]; className?: string }) {
  return (
    <dl className={cx(styles.list, className)}>
      {items.map((item) => (
        <div key={item.label} className={styles.row}>
          <dt className={styles.label}>{item.label}</dt>
          <dd className={cx(styles.value, item.mono && styles.mono)}>
            {item.value}
          </dd>
        </div>
      ))}
    </dl>
  );
}
