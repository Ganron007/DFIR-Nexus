/**
 * Command palette (WO-U3): Ctrl+K.
 *
 * An examiner who knows the finding id should not have to walk the nav to reach
 * it, and one who knows the page name should not have to hunt the sidebar. The
 * palette takes its commands from the shell, so the nav and the palette can
 * never list different pages.
 */
import { useCallback, useEffect, useMemo, useRef, useState } from "react";

export interface PaletteCommand {
  id: string;
  label: string;
  group: "Go to" | "Finding" | "Search";
  hint?: string;
  run: () => void;
}

interface Props {
  commands: PaletteCommand[];
  /** Called when the examiner asks for a finding id or a search term. */
  onResolveFinding?: (id: string) => void;
  onSearch?: (query: string) => void;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

const FINDING_RE = /^(?:F-|finding\s*)/i;

export function CommandPalette({
  commands,
  onResolveFinding,
  onSearch,
  open,
  onOpenChange,
}: Props) {
  const [term, setTerm] = useState("");
  const [cursor, setCursor] = useState(0);
  const inputRef = useRef<HTMLInputElement | null>(null);

  useEffect(() => {
    if (open) {
      setTerm("");
      setCursor(0);
      // focus after paint: the dialog is mounted by this state
      const id = window.setTimeout(() => inputRef.current?.focus(), 0);
      return () => window.clearTimeout(id);
    }
    return undefined;
  }, [open]);

  const matches = useMemo(() => {
    const needle = term.trim().toLowerCase();
    if (!needle) return commands;
    return commands.filter(
      (c) =>
        c.label.toLowerCase().includes(needle) ||
        (c.hint ?? "").toLowerCase().includes(needle),
    );
  }, [commands, term]);

  const submit = useCallback(
    (command: PaletteCommand) => {
      onOpenChange(false);
      command.run();
    },
    [onOpenChange],
  );

  const onKeyDown = useCallback(
    (event: React.KeyboardEvent<HTMLDivElement>) => {
      if (event.key === "Escape") {
        onOpenChange(false);
        return;
      }
      if (event.key === "ArrowDown") {
        event.preventDefault();
        setCursor((c) => Math.min(matches.length - 1, c + 1));
        return;
      }
      if (event.key === "ArrowUp") {
        event.preventDefault();
        setCursor((c) => Math.max(0, c - 1));
        return;
      }
      if (event.key === "Enter") {
        event.preventDefault();
        const chosen = matches[cursor] ?? matches[0];
        const text = term.trim();
        // A typed finding id goes where it was asked for; a typed phrase searches.
        if (text && FINDING_RE.test(text) && onResolveFinding) {
          onOpenChange(false);
          onResolveFinding(text.replace(/^finding\s*/i, ""));
          return;
        }
        if (chosen) {
          submit(chosen);
          return;
        }
        if (text && onSearch) {
          onOpenChange(false);
          onSearch(text);
        }
      }
    },
    [cursor, matches, onOpenChange, onResolveFinding, onSearch, submit, term],
  );

  if (!open) return null;

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-label="Command palette"
      data-testid="command-palette"
      onKeyDown={onKeyDown}
      style={{
        position: "fixed",
        inset: 0,
        zIndex: 1000,
        background: "rgba(2, 6, 23, 0.55)",
        display: "flex",
        alignItems: "flex-start",
        justifyContent: "center",
        paddingTop: "12vh",
      }}
    >
      <div
        style={{
          width: "min(640px, 92vw)",
          background: "var(--color-bg-overlay)",
          border: "1px solid var(--color-border-default)",
          borderRadius: "var(--radius-lg)",
          boxShadow: "var(--shadow-2, 0 24px 60px rgba(0,0,0,0.45))",
          overflow: "hidden",
        }}
      >
        <input
          ref={inputRef}
          data-testid="command-palette-input"
          aria-label="Go to a page, a finding id, or search"
          placeholder="Go to a page, a finding id (F-…), or type to search"
          value={term}
          onChange={(e) => {
            setTerm(e.target.value);
            setCursor(0);
          }}
          style={{
            width: "100%",
            border: 0,
            borderBottom: "1px solid var(--color-border-default)",
            background: "transparent",
            color: "var(--color-fg-default)",
            font: "inherit",
            padding: "var(--space-3) var(--space-4)",
            outline: "none",
          }}
        />
        <ul
          role="listbox"
          aria-label="Commands"
          style={{ listStyle: "none", margin: 0, padding: "var(--space-2)", maxHeight: "46vh", overflowY: "auto" }}
        >
          {matches.length === 0 ? (
            <li
              data-testid="command-palette-empty"
              style={{ padding: "var(--space-3)", color: "var(--color-fg-muted)", fontSize: "var(--font-size-sm)" }}
            >
              Nothing matches “{term.trim()}”.
            </li>
          ) : null}
          {matches.map((command, index) => (
            <li key={command.id} role="option" aria-selected={index === cursor}>
              <button
                type="button"
                data-testid={`command-${command.id}`}
                onMouseEnter={() => setCursor(index)}
                onClick={() => submit(command)}
                style={{
                  display: "flex",
                  width: "100%",
                  gap: "var(--space-3)",
                  alignItems: "baseline",
                  textAlign: "left",
                  border: 0,
                  borderRadius: "var(--radius-md)",
                  padding: "var(--space-2) var(--space-3)",
                  cursor: "pointer",
                  font: "inherit",
                  background: index === cursor ? "var(--bg-hover)" : "transparent",
                  color: "var(--color-fg-default)",
                }}
              >
                <span
                  style={{
                    fontSize: "var(--font-size-2xs, 0.625rem)",
                    textTransform: "uppercase",
                    letterSpacing: "0.06em",
                    color: "var(--color-fg-subtle)",
                    minWidth: "4.5rem",
                  }}
                >
                  {command.group}
                </span>
                <span>{command.label}</span>
                {command.hint ? (
                  <span style={{ marginLeft: "auto", fontSize: "var(--font-size-xs)", color: "var(--color-fg-subtle)" }}>
                    {command.hint}
                  </span>
                ) : null}
              </button>
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}