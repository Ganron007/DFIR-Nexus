import {
  createContext,
  useCallback,
  useContext,
  useMemo,
  useState,
  type CSSProperties,
  type ReactNode,
} from "react";
import * as RadixToast from "@radix-ui/react-toast";
import { SEMANTIC_TONES, type SemanticTone } from "./semantic";
import styles from "./Toast.module.css";

export interface ToastOptions {
  title: string;
  detail?: ReactNode;
  tone?: SemanticTone;
  duration?: number;
}

interface ToastContextValue {
  push: (options: ToastOptions) => void;
}

const ToastContext = createContext<ToastContextValue | null>(null);

export function useToast(): ToastContextValue {
  const ctx = useContext(ToastContext);
  if (!ctx) {
    throw new Error("useToast must be used inside <ToastProvider>");
  }
  return ctx;
}

interface QueuedToast extends ToastOptions {
  id: number;
  open: boolean;
}

/** Mount once in the shell (U3). Pages push via useToast(). */
export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<QueuedToast[]>([]);
  const nextId = useMemo(() => {
    let id = 0;
    return () => ++id;
  }, []);

  const push = useCallback(
    (options: ToastOptions) => {
      const id = nextId();
      setToasts((current) => [...current, { ...options, id, open: true }]);
    },
    [nextId],
  );

  const value = useMemo(() => ({ push }), [push]);

  return (
    <ToastContext.Provider value={value}>
      <RadixToast.Provider swipeDirection="right">
        {children}
        {toasts.map((toast) => (
          <RadixToast.Root
            key={toast.id}
            open={toast.open}
            duration={toast.duration ?? 5000}
            onOpenChange={(open) => {
              setToasts((current) =>
                open
                  ? current
                  : current.map((t) => (t.id === toast.id ? { ...t, open } : t)),
              );
            }}
            className={styles.toast}
            style={
              toast.tone
                ? ({
                    "--tone-accent": `var(${SEMANTIC_TONES[toast.tone]})`,
                  } as CSSProperties)
                : undefined
            }
          >
            <div className={styles.titleRow}>
              <RadixToast.Title className={styles.title}>{toast.title}</RadixToast.Title>
              <RadixToast.Close className={styles.close} aria-label="Dismiss">
                ×
              </RadixToast.Close>
            </div>
            {toast.detail ? (
              <RadixToast.Description className={styles.detail}>
                {toast.detail}
              </RadixToast.Description>
            ) : null}
          </RadixToast.Root>
        ))}
        <RadixToast.Viewport className={styles.viewport} />
      </RadixToast.Provider>
    </ToastContext.Provider>
  );
}
