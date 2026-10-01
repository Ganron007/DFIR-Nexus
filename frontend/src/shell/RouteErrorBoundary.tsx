/**
 * Per-route error boundary (WO-U3).
 *
 * A page that throws used to blank the whole cockpit: one bad row in one
 * artifact took the examiner's nav, the gate banner and every other page with
 * it. The boundary scopes the failure to the route, names it, and offers a
 * retry that remounts the page - and it resets on navigation, because the next
 * route deserves a fresh attempt rather than the previous one's stack.
 *
 * react-router v6 removed `withRouter`, so the location is read with a hook and
 * passed down as a plain prop.
 */
import { Component, type ErrorInfo, type ReactNode } from "react";
import { useLocation } from "react-router-dom";

interface Props {
  children: ReactNode;
  /** Shown in the fallback so the examiner can say which surface failed. */
  routeName?: string;
}

interface State {
  error: Error | null;
  info: string;
}

export class RouteErrorBoundaryInner extends Component<Props & { locationKey?: string }, State> {
  state: State = { error: null, info: "" };

  static getDerivedStateFromError(error: Error): Partial<State> {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo): void {
    // The component stack is development-only; the message is the durable part.
    this.setState({ info: info.componentStack?.slice(0, 400) ?? "" });
    if (import.meta.env.DEV) {
      // eslint-disable-next-line no-console
      console.error("route boundary caught:", error);
    }
  }

  componentDidUpdate(prev: Props & { locationKey?: string }): void {
    if (prev.locationKey !== this.props.locationKey && this.state.error) {
      this.setState({ error: null, info: "" });
    }
  }

  render(): ReactNode {
    const { error, info } = this.state;
    if (!error) return this.props.children;
    return (
      <div role="alert" data-testid="route-error" style={{ padding: "var(--space-5)" }}>
        <h2 style={{ marginBottom: "var(--space-2)" }}>
          {this.props.routeName ?? "This page"} could not be shown
        </h2>
        <p style={{ color: "var(--color-fg-muted)" }}>
          The error is contained to this route - your case data is untouched and
          the rest of the cockpit still works.
        </p>
        <pre
          data-testid="route-error-message"
          style={{
            marginTop: "var(--space-3)",
            fontFamily: "var(--font-mono)",
            fontSize: "var(--font-size-xs)",
            color: "var(--danger)",
            whiteSpace: "pre-wrap",
          }}
        >
          {error.message}
        </pre>
        {import.meta.env.DEV && info ? (
          <pre style={{ fontSize: "var(--font-size-xs)", color: "var(--color-fg-subtle)" }}>
            {info}
          </pre>
        ) : null}
        <button
          type="button"
          className="btn btn-sm"
          data-testid="route-error-retry"
          onClick={() => this.setState({ error: null, info: "" })}
        >
          Try again
        </button>
      </div>
    );
  }
}

export function RouteErrorBoundary(props: Props): ReactNode {
  const location = useLocation();
  return (
    <RouteErrorBoundaryInner
      {...props}
      locationKey={location.key || location.pathname}
    />
  );
}