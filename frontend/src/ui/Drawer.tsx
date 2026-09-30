import type { ReactNode } from "react";
import * as RadixDialog from "@radix-ui/react-dialog";
import styles from "./Drawer.module.css";

export interface DrawerProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: string;
  children: ReactNode;
  width?: number;
}

/**
 * Right-side sheet (Radix Dialog). Focus trap, Esc-to-close and focus return
 * to the trigger are Radix behaviour — do not reimplement them.
 */
export function Drawer({ open, onOpenChange, title, children, width = 520 }: DrawerProps) {
  return (
    <RadixDialog.Root open={open} onOpenChange={onOpenChange}>
      <RadixDialog.Portal>
        <RadixDialog.Overlay className={styles.overlay} />
        <RadixDialog.Content
          className={styles.content}
          style={{ width }}
          aria-describedby={undefined}
        >
          <header className={styles.header}>
            <RadixDialog.Title className={styles.title}>{title}</RadixDialog.Title>
            <RadixDialog.Close className={styles.close} aria-label="Close">
              ×
            </RadixDialog.Close>
          </header>
          <div className={styles.body}>{children}</div>
        </RadixDialog.Content>
      </RadixDialog.Portal>
    </RadixDialog.Root>
  );
}
