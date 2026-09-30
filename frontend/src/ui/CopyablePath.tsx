import { Tooltip } from "./Tooltip";
import { copyText } from "./CopyableHash";
import styles from "./CopyablePath.module.css";

/** Middle-ellipsis a long path, keeping both ends visible. */
export function middleEllipsis(value: string, max = 60): string {
  if (value.length <= max) {
    return value;
  }
  const head = Math.ceil((max - 1) / 2);
  const tail = Math.floor((max - 1) / 2);
  return `${value.slice(0, head)}…${value.slice(value.length - tail)}`;
}

/**
 * Long filesystem paths render middle-ellipsised (`C:\…\evtx\Security.evtx`)
 * with the full path in the tooltip and a copy button.
 */
export function CopyablePath({ value, max = 60 }: { value: string; max?: number }) {
  return (
    <span className={styles.row}>
      <Tooltip content={value}>
        <span className={styles.path}>{middleEllipsis(value, max)}</span>
      </Tooltip>
      <button
        type="button"
        className={styles.copy}
        aria-label={`Copy path ${value}`}
        onClick={() => void copyText(value)}
      >
        copy
      </button>
    </span>
  );
}
