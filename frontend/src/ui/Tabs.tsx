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
  /** Panels, one `TabPanel` per item value. */
  children?: ReactNode;
}

/**
 * Controlled tab strip (Radix Tabs — roving focus and arrow-key navigation
 * are built in).
 *
 * The panels go inside this Root as `TabPanel` children. Rendering them
 * outside would leave every trigger's `aria-controls` pointing at an element
 * that does not exist — an accessibility defect, not a style choice.
 */
export function Tabs({ items, value, onValueChange, label, className, children }: TabsProps) {
  return (
    <RadixTabs.Root value={value} onValueChange={onValueChange} className={className}>
      <RadixTabs.List aria-label={label} className={styles.list}>
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
      {children}
    </RadixTabs.Root>
  );
}

/**
 * One tab panel. Force-mounted so its id exists for the trigger's
 * `aria-controls`; Radix hides the inactive ones with the `hidden` attribute.
 */
export function TabPanel({ value, children }: { value: string; children: ReactNode }) {
  return (
    <RadixTabs.Content value={value} forceMount className={styles.panel}>
      {children}
    </RadixTabs.Content>
  );
}
