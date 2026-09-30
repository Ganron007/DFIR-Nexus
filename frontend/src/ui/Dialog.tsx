import type { ReactNode } from "react";
import * as RadixDialog from "@radix-ui/react-dialog";
import { Button } from "./Button";
import { cx } from "./cx";
import styles from "./Dialog.module.css";

export interface DialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: string;
  children: ReactNode;
  className?: string;
}

/** Modal dialog (Radix Dialog — focus trap, Esc, focus return built in). */
export function Dialog({ open, onOpenChange, title, children, className }: DialogProps) {
  return (
    <RadixDialog.Root open={open} onOpenChange={onOpenChange}>
      <RadixDialog.Portal>
        <RadixDialog.Overlay className={styles.overlay} />
        <RadixDialog.Content
          className={cx(styles.content, className)}
          aria-describedby={undefined}
        >
          <RadixDialog.Title className={styles.title}>{title}</RadixDialog.Title>
          {children}
        </RadixDialog.Content>
      </RadixDialog.Portal>
    </RadixDialog.Root>
  );
}

export interface ConfirmDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: string;
  body: ReactNode;
  confirmLabel?: string;
  cancelLabel?: string;
  /** danger renders the confirm button in the destructive style. */
  tone?: "primary" | "danger";
  onConfirm: () => void;
}

/** Confirmation modal for destructive or consequential actions. */
export function ConfirmDialog({
  open,
  onOpenChange,
  title,
  body,
  confirmLabel = "Confirm",
  cancelLabel = "Cancel",
  tone = "primary",
  onConfirm,
}: ConfirmDialogProps) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange} title={title}>
      <div className={styles.body}>{body}</div>
      <div className={styles.actions}>
        <Button onClick={() => onOpenChange(false)}>{cancelLabel}</Button>
        <Button
          variant={tone === "danger" ? "danger" : "primary"}
          onClick={() => {
            onConfirm();
            onOpenChange(false);
          }}
        >
          {confirmLabel}
        </Button>
      </div>
    </Dialog>
  );
}
