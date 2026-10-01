import "@testing-library/jest-dom/vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { CommandPalette, type PaletteCommand } from "./CommandPalette";
import { RouteErrorBoundary } from "./RouteErrorBoundary";
import {
  CASE_PAGES,
  caseIdFromPath,
  casePath,
  isCockpitPath,
  pageFor,
  pageFromPath,
} from "./caseScope";

// --------------------------------------------------------------------------
// case-scoped paths (UD8)
// --------------------------------------------------------------------------

describe("caseScope", () => {
  it("scopes a page to a case and round-trips the id", () => {
    expect(casePath("CASE-9F2A1B", "explore")).toBe("/case/CASE-9F2A1B/explore");
    expect(caseIdFromPath("/case/CASE-9F2A1B/explore")).toBe("CASE-9F2A1B");
    expect(pageFromPath("/case/CASE-9F2A1B/explore")).toBe("explore");
  });

  it("degrades to the legacy path when there is no case", () => {
    expect(casePath("", "findings")).toBe("/findings");
    expect(caseIdFromPath("/explore")).toBeNull();
  });

  it("escapes an id that needs it", () => {
    expect(casePath("CASE-A/B", "report")).toBe("/case/CASE-A%2FB/report");
    expect(caseIdFromPath("/case/CASE-A%2FB/report")).toBe("CASE-A/B");
  });

  it("knows which legacy paths are cockpit pages, and which are not", () => {
    for (const page of CASE_PAGES) {
      expect(pageFor(`/${page}`)).toBe(page);
      expect(isCockpitPath(`/${page}`)).toBe(true);
    }
    expect(pageFor("/")).toBeNull();
    expect(pageFor("/case-setup")).toBeNull();
    expect(pageFor("/explore/extra")).toBeNull();
    expect(isCockpitPath("/case-setup")).toBe(false);
  });
});

// --------------------------------------------------------------------------
// the command palette
// --------------------------------------------------------------------------

const COMMANDS: PaletteCommand[] = [
  { id: "/explore", label: "Explore", group: "Go to", hint: "search", run: vi.fn() },
  { id: "/findings", label: "Findings", group: "Go to", run: vi.fn() },
  { id: "/approve", label: "Approve", group: "Go to", run: vi.fn() },
];

function renderPalette(overrides: Partial<React.ComponentProps<typeof CommandPalette>> = {}) {
  const onOpenChange = vi.fn();
  const result = render(
    <MemoryRouter>
      <CommandPalette
        commands={COMMANDS}
        open
        onOpenChange={onOpenChange}
        {...overrides}
      />
    </MemoryRouter>,
  );
  return { ...result, onOpenChange };
}

describe("CommandPalette", () => {
  beforeEach(() => vi.clearAllMocks());

  it("lists the commands it was given, grouped", () => {
    renderPalette();
    expect(screen.getByTestId("command-palette")).toBeInTheDocument();
    expect(screen.getByTestId("command-/explore")).toBeInTheDocument();
    // one group label per command, and every command is on the list
    expect(screen.getAllByText("Go to")).toHaveLength(COMMANDS.length);
    for (const command of COMMANDS) {
      expect(screen.getByTestId(`command-${command.id}`)).toBeInTheDocument();
    }
  });

  it("filters as the examiner types and says when nothing matches", async () => {
    const user = userEvent.setup();
    renderPalette();
    await user.type(screen.getByTestId("command-palette-input"), "appro");
    expect(screen.queryByTestId("command-/explore")).not.toBeInTheDocument();
    expect(screen.getByTestId("command-/approve")).toBeInTheDocument();

    await user.clear(screen.getByTestId("command-palette-input"));
    await user.type(screen.getByTestId("command-palette-input"), "zzzz");
    expect(screen.getByTestId("command-palette-empty")).toBeInTheDocument();
  });

  it("runs the chosen command and closes", async () => {
    const user = userEvent.setup();
    const run = vi.fn();
    const { onOpenChange } = renderPalette({
      commands: [{ id: "x", label: "Timeline", group: "Go to", run }],
    });
    await user.click(screen.getByTestId("command-x"));
    expect(run).toHaveBeenCalledTimes(1);
    expect(onOpenChange).toHaveBeenCalledWith(false);
  });

  it("sends a typed finding id to the finding route, not to a command", async () => {
    const user = userEvent.setup();
    const onResolveFinding = vi.fn();
    const run = vi.fn();
    renderPalette({
      commands: [{ id: "x", label: "Timeline", group: "Go to", run }],
      onResolveFinding,
    });
    await user.type(screen.getByTestId("command-palette-input"), "F-abc123{Enter}");
    expect(onResolveFinding).toHaveBeenCalledWith("F-abc123");
    expect(run).not.toHaveBeenCalled();
  });

  it("searches when there is no command for what was typed", async () => {
    const user = userEvent.setup();
    const onSearch = vi.fn();
    renderPalette({ onSearch });
    await user.type(screen.getByTestId("command-palette-input"), "mimikatz{Enter}");
    expect(onSearch).toHaveBeenCalledWith("mimikatz");
  });

  it("closes on Escape", async () => {
    const user = userEvent.setup();
    const { onOpenChange } = renderPalette();
    await user.keyboard("{Escape}");
    expect(onOpenChange).toHaveBeenCalledWith(false);
  });

  it("renders nothing when closed", () => {
    render(
      <MemoryRouter>
        <CommandPalette commands={COMMANDS} open={false} onOpenChange={vi.fn()} />
      </MemoryRouter>,
    );
    expect(screen.queryByTestId("command-palette")).not.toBeInTheDocument();
  });
});

// --------------------------------------------------------------------------
// the per-route error boundary
// --------------------------------------------------------------------------

function Boom({ message = "artifact row blew up" }: { message?: string }): never {
  throw new Error(message);
}

describe("RouteErrorBoundary", () => {
  beforeEach(() => {
    // the boundary logs in dev; keep the run's output readable
    vi.spyOn(console, "error").mockImplementation(() => undefined);
  });

  it("contains a throwing page and names the route", () => {
    render(
      <MemoryRouter initialEntries={["/case/CASE-1/explore"]}>
        <RouteErrorBoundary routeName="Explore">
          <Boom />
        </RouteErrorBoundary>
      </MemoryRouter>,
    );
    expect(screen.getByTestId("route-error")).toBeInTheDocument();
    expect(screen.getByText("Explore could not be shown")).toBeInTheDocument();
    expect(screen.getByTestId("route-error-message")).toHaveTextContent(
      "artifact row blew up",
    );
  });

  it("keeps healthy children untouched", () => {
    render(
      <MemoryRouter>
        <RouteErrorBoundary routeName="Explore">
          <p>the page</p>
        </RouteErrorBoundary>
      </MemoryRouter>,
    );
    expect(screen.getByText("the page")).toBeInTheDocument();
    expect(screen.queryByTestId("route-error")).not.toBeInTheDocument();
  });

  it("retries on demand", async () => {
    const user = userEvent.setup();
    let shouldThrow = true;
    function Flaky() {
      if (shouldThrow) throw new Error("first attempt failed");
      return <p>recovered</p>;
    }
    render(
      <MemoryRouter>
        <RouteErrorBoundary routeName="Explore">
          <Flaky />
        </RouteErrorBoundary>
      </MemoryRouter>,
    );
    expect(screen.getByTestId("route-error")).toBeInTheDocument();
    shouldThrow = false;
    await user.click(screen.getByTestId("route-error-retry"));
    expect(screen.getByText("recovered")).toBeInTheDocument();
  });
});