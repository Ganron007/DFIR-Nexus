import type { ReactNode } from "react";
import * as RadixTabs from "@radix-ui/react-tabs";
import styles from "./Tabs.module.css";

export interface TabItem {
  value: string;
  label: ReactNode;
  disabled?: boolean;
}

export interface TabsProps {
  items: TabItem[];
  value: string;
  onValueChange: (value: string) => void;
  /** Accessible name for the tab list. */
  label: string;
  className?: string;
}

/**
 * Controlled tab strip (Radix Tabs — roving focus and arrow-key navigation
 * are built in). Content is rendered by the caller; this component is the
 * trigger list only.
 */
export function Tabs({ items, value, onValueChange, label, className }: TabsProps) {
  return (
    <RadixTabs.Root value={value} onValueChange={onValueChange} className={className}>      <RadixTabs.List aria-label={label} className={styles.list}>
        {items.map((item) => (
          <RadixTabs.Trigger
            key={item.value}
            value={item.value}
            disabled={item.disabled}
            className={styles.trigger}
          >
            {item.label}
          </RadixTabs.Trigger>
        ))}
      </RadixTabs.List>
    </RadixTabs.Root>
  );
}
