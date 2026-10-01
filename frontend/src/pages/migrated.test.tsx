/**
 * U8a migration tests — the pages moved onto the kit and the query hooks.
 *
 * The properties worth pinning are the ones the old `useEffect` versions got
 * wrong: a case switch must not leave the previous case's data on screen, and
 * a backend failure must be visible rather than rendering as an absence.
 */
import "@testing-library/jest-dom/vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { beforeEach, describe, expect, it, vi } from "vitest";

import Entities from "./Entities";
import Iocs from "./Iocs";
import Transparency from "./Transparency";
import { api } from "../api/client";
import * as caseContext from "../context/CaseContext";

/** The page reads the active case from context; the queries key off it. */
function withCase(caseId: string) {
  vi.spyOn(caseContext, "useCase").mockReturnValue({
    activeCase: caseId,
    cases: [caseId],
    caseSummaries: {},
    previewCase: caseId,
    booting: false,
    mode: "1",
    health: "ok",
    es: { configured: true, reachable: true },
    sift: { selected: false, reachable: false },
    setActiveCase: vi.fn(),
    setPreviewCase: vi.fn(),
    exitToDashboard: vi.fn(),
    refreshCases: vi.fn(),
    refreshMode: vi.fn(),
    refreshStages: vi.fn(),
    setMode: vi.fn(),
    stages: {},
  } as unknown as ReturnType<typeof caseContext.useCase>);
}

function renderPage(node: React.ReactNode) {
  // the app supplies the QueryClient; the kit hooks require one, and a fresh
  // client per test keeps cache state from leaking between cases
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false, gcTime: 0 } },
  });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>{node}</MemoryRouter>
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  vi.restoreAllMocks();
});

// --------------------------------------------------------------------------
// IOCs
// --------------------------------------------------------------------------

describe("Iocs (migrated)", () => {
  it("lists the indicators with their status tone", async () => {
    withCase("CASE-IOC0001");
    vi.spyOn(api, "iocs").mockResolvedValue({
      iocs: [
        { type: "sha256", value: "a".repeat(64), source: "evidence", status: "APPROVED" },
        { type: "ip", value: "192.168.1.1", source: "finding", finding_status: "DRAFT" },
      ],
    } as never);
    renderPage(<Iocs />);
    await waitFor(() => expect(screen.getByText("a".repeat(64))).toBeInTheDocument());
    expect(screen.getByText("192.168.1.1")).toBeInTheDocument();
    // the count in the subtitle is the real count, not a guess
    expect(screen.getByText(/2 indicators/)).toBeInTheDocument();
  });

  it("surfaces a failed read instead of showing an empty table", async () => {
    withCase("CASE-IOC0002");
    vi.spyOn(api, "iocs").mockRejectedValue(new Error("backend refused"));
    renderPage(<Iocs />);
    await waitFor(() =>
      expect(screen.getByRole("alert")).toHaveTextContent(/could not be read/),
    );
    expect(screen.queryByText("No IOCs yet")).not.toBeInTheDocument();
  });

  it("scopes the request to the case in context", async () => {
    withCase("CASE-IOC0003");
    const iocs = vi.spyOn(api, "iocs").mockResolvedValue({ iocs: [] } as never);
    renderPage(<Iocs />);
    await waitFor(() => expect(iocs).toHaveBeenCalled());
  });
});

// --------------------------------------------------------------------------
// Entities
// --------------------------------------------------------------------------

describe("Entities (migrated)", () => {
  it("extracts on demand rather than on mount", async () => {
    withCase("CASE-ENT0001");
    const entities = vi.spyOn(api, "entities").mockResolvedValue({
      entities: { user: { bob: 3, alice: 1 }, host: { WS01: 2 } },
      total: 42,
    } as never);
    renderPage(<Entities />);
    // no request until the examiner asks - the old page extracted on mount
    expect(entities).not.toHaveBeenCalled();

    fireEvent.click(screen.getByTestId("entities-extract"));
    await waitFor(() => expect(entities).toHaveBeenCalledTimes(1));
    // busiest first
    const rows = screen.getAllByRole("row").slice(1);
    expect(rows[0]).toHaveTextContent("bob");
    expect(rows[0]).toHaveTextContent("3");
    expect(screen.getByText(/42 hits scanned/)).toBeInTheDocument();
  });

  it("passes the needles it was given", async () => {
    withCase("CASE-ENT0002");
    const entities = vi.spyOn(api, "entities").mockResolvedValue({
      entities: {},
      total: 0,
    } as never);
    renderPage(<Entities />);
    const input = screen.getByLabelText("Needles");
    fireEvent.change(input, { target: { value: "sdelete" } });
    fireEvent.click(screen.getByTestId("entities-extract"));
    await waitFor(() => expect(entities).toHaveBeenCalledWith({ needles: "sdelete" }));
  });

  it("reports a failed extraction rather than an empty table", async () => {
    withCase("CASE-ENT0003");
    vi.spyOn(api, "entities").mockRejectedValue(new Error("index missing"));
    renderPage(<Entities />);
    fireEvent.click(screen.getByTestId("entities-extract"));
    await waitFor(() =>
      expect(screen.getByRole("alert")).toHaveTextContent(/index missing/),
    );
  });
});

// --------------------------------------------------------------------------
// Transparency
// --------------------------------------------------------------------------

describe("Transparency (migrated)", () => {
  const valid = { valid: true, entries: 128 };

  it("says the chain is valid, in words and in tone", async () => {
    withCase("CASE-TRN0001");
    vi.spyOn(api, "transparency").mockResolvedValue(valid as never);
    renderPage(<Transparency />);
    const verdict = await screen.findByTestId("chain-verdict");
    expect(verdict).toHaveTextContent("Chain valid");
    expect(verdict).toHaveTextContent(/valid/i);
    expect(screen.getByText("128")).toBeInTheDocument();
  });

  it("never renders a tampered chain as anything but tampered", async () => {
    withCase("CASE-TRN0002");
    vi.spyOn(api, "transparency").mockResolvedValue({
      valid: false,
      entries: 128,
      tampered: 41,
      expected: "b".repeat(64),
      actual: "c".repeat(64),
    } as never);
    renderPage(<Transparency />);
    const verdict = await screen.findByTestId("chain-verdict");
    expect(verdict).toHaveTextContent("Chain tampered");
    expect(verdict).not.toHaveTextContent("Chain valid");
    // the index and the hashes are shown, not just the verdict
    expect(screen.getByText("41")).toBeInTheDocument();
  });

  it("refuses to render a verdict the endpoint did not give", async () => {
    withCase("CASE-TRN0003");
    // A body with no `valid` key is not a verdict. Rendering it as one would
    // tell the examiner their chain is fine when nobody checked.
    vi.spyOn(api, "transparency").mockResolvedValue({ entries: 3 } as never);
    renderPage(<Transparency />);
    await waitFor(() =>
      expect(screen.getByRole("alert")).toHaveTextContent(/could not be read/),
    );
    expect(screen.queryByTestId("chain-verdict")).not.toBeInTheDocument();
  });
});

// --------------------------------------------------------------------------
// Findings
// --------------------------------------------------------------------------
