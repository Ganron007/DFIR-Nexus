/**
 * Steer Chat migration (WO-U8a) — the accessibility gains.
 *
 * The WO asked for labelled controls and message components. Both are pinned
 * here because both are the kind of thing that silently regresses: a control
 * can lose its label in a refactor and the page still looks right.
 */
import "@testing-library/jest-dom/vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

import SteerChat, { dslToExplore, answerTitle } from "./SteerChat";
import { api } from "../api/client";
import * as caseContext from "../context/CaseContext";

const ANSWER = {
  ts: "2026-09-30T10:00:00Z",
  role: "llm",
  action: "steer_answer",
  text: "## What ran\n\nTwo rows matched.",
  meta: { total_hits: "2" },
  data: {
    queries: [{ tool: "es_search", dsl: "family:evtx AND powershell", hits: 2, why: "narrow to execution" }],
    followups: [{ label: "Wider window", question: "widen the window to an hour" }],
    partial: false,
  },
};

function withCase(caseId: string, mode = "1") {
  vi.spyOn(caseContext, "useCase").mockReturnValue({
    activeCase: caseId,
    cases: [caseId],
    caseSummaries: {},
    previewCase: caseId,
    booting: false,
    mode,
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
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false, gcTime: 0 } },
  });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>{node}</MemoryRouter>
    </QueryClientProvider>,
  );
}

function stubReads(messages = [ANSWER]) {
  vi.spyOn(api, "chat").mockResolvedValue({ messages, total: messages.length } as never);
  vi.spyOn(api, "mode1Suggestions").mockResolvedValue({
    suggestions: [{ text: "who ran mshta?", source: "deterministic" }],
    generated_by: "deterministic",
  } as never);
}

beforeEach(() => {
  vi.restoreAllMocks();
});

describe("Steer Chat (migrated)", () => {
  it("labels the composer — a placeholder is not a label", async () => {
    withCase("CASE-ST0001");
    stubReads([]);
    renderPage(<SteerChat />);
    const input = await screen.findByLabelText("Ask about the evidence");
    expect(input).toBeInTheDocument();
    expect(input).toHaveAttribute("placeholder");
  });

  it("labels the iteration-depth control", async () => {
    withCase("CASE-ST0002");
    stubReads([]);
    renderPage(<SteerChat />);
    const rounds = await screen.findByLabelText("Max rounds");
    expect(rounds).toHaveAttribute("type", "number");
    expect(rounds).toHaveAttribute("min", "1");
    // The control reaches the loop's own ceiling (D9), not an arbitrary 4.
    expect(rounds).toHaveAttribute("max", "8");
  });

  it("makes the transcript a live region so a streamed answer is announced", async () => {
    withCase("CASE-ST0003");
    stubReads([]);
    renderPage(<SteerChat />);
    const transcript = await screen.findByTestId("transcript");
    expect(transcript).toHaveAttribute("role", "log");
    expect(transcript).toHaveAttribute("aria-live", "polite");
  });

  it("shows the query trace with its why, as its own component", async () => {
    withCase("CASE-ST0004");
    stubReads();
    renderPage(<SteerChat />);
    const trace = await screen.findByTestId("query-trace");
    expect(trace).toHaveTextContent("family:evtx AND powershell");
    expect(trace).toHaveTextContent("2 hit(s)");
    expect(trace).toHaveTextContent("narrow to execution");
  });

  it("shows the drill-down chips for the next turn", async () => {
    withCase("CASE-ST0005");
    stubReads();
    renderPage(<SteerChat />);
    await waitFor(() => expect(screen.getByText("Wider window")).toBeInTheDocument());
  });

  it("says an answer was partial, rather than looking complete", async () => {
    withCase("CASE-ST0006");
    stubReads([
      {
        ...ANSWER,
        data: { ...ANSWER.data, partial: true },
      },
    ]);
    renderPage(<SteerChat />);
    expect(await screen.findByTestId("partial-notice")).toBeInTheDocument();
  });

  it("shows suggestions and where they came from", async () => {
    withCase("CASE-ST0007");
    stubReads([]);
    renderPage(<SteerChat />);
    const panel = await screen.findByTestId("suggestions");
    expect(panel).toHaveTextContent("who ran mshta?");
    expect(panel).toHaveTextContent("deterministic");
  });

  it("sends a Mode 2/3 case to Agent Run instead of pretending to chat", async () => {
    withCase("CASE-ST0008", "2");
    stubReads([]);
    renderPage(<SteerChat />);
    await waitFor(() =>
      expect(screen.getByText(/Mode 2 \(multi-role\)/)).toBeInTheDocument(),
    );
    expect(screen.getByText("Open Agent Run")).toBeInTheDocument();
  });

  it("surfaces a failed transcript read", async () => {
    withCase("CASE-ST0009");
    stubReads([]);
    // after stubReads, so the rejection is the one that stands
    vi.spyOn(api, "chat").mockRejectedValue(new Error("transcript unavailable"));
    renderPage(<SteerChat />);
    await waitFor(() =>
      expect(screen.getByRole("alert")).toHaveTextContent("transcript unavailable"),
    );
  });
});

describe("dslToExplore", () => {
  it("scopes the URL to the case and carries the needles", () => {
    const url = dslToExplore("family:evtx AND powershell -enc", "CASE-ST0010");
    expect(url.startsWith("/case/CASE-ST0010/explore?")).toBe(true);
    expect(url).toContain("needles=");
    expect(url).toContain("family=evtx");
    // the boolean and the field qualifiers must not leak into the needles
    expect(url).not.toContain("AND");
  });

  it("falls back to a plain Explore path with no case", () => {
    expect(dslToExplore("", "")).toBe("/explore");
  });
});

describe("answerTitle", () => {
  it("takes the first meaningful line and strips markdown", () => {
    expect(answerTitle("## Heading\n\n**Bold claim** here")).toBe("Bold claim here");
  });

  it("never returns an empty title", () => {
    expect(answerTitle("")).toBe("Mode 1 answer");
    expect(answerTitle("| a | b |")).toBe("Mode 1 answer");
  });
});