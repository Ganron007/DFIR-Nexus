import { useState } from "react";
import { Tooltip } from "./Tooltip";
import styles from "./CopyableHash.module.css";

async function copyText(value: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(value);
    return true;
  } catch {
    return false;
  }
}

/**
 * SHA-256 shown shortened (12 chars), full value in the tooltip, click the
 * button to copy the full hash.
 */
export function CopyableHash({ value, className }: { value: string; className?: string }) {
  const [copied, setCopied] = useState(false);
  const short = value.length > 12 ? `${value.slice(0, 12)}` : value;

  return (
    <span className={className}>
      <Tooltip content={copied ? "Copied" : value}>
        <button
          type="button"
          className={styles.button}
          aria-label={`Copy hash ${short}`}
          onClick={async () => {
            if (await copyText(value)) {
              setCopied(true);
              window.setTimeout(() => setCopied(false), 1500);
            }
          }}
        >
          <span className={styles.hash}>{short}</span>
        </button>
      </Tooltip>
    </span>
  );
}

export { copyText };
