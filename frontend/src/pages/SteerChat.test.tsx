import { describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";

vi.mock("../api/client", () => ({
  api: {
    chat: vi.fn(async () => ({
      messages: [{
        ts: "2026-09-25T00:00:00Z",
        role: "llm",
        action: "steer_answer",
        text: "Found rows before the budget expired.",
        meta: {},
        data: { partial: true, queries: [] },
      }],
      total: 1,
    })),
    chatClear: vi.fn(async () => ({ status: "cleared" })),
    mode2Suggestions: vi.fn(async () => ({ suggestions: [], generated_by: "deterministic" })),
    mode2SaveAnswer: vi.fn(async () => ({ status: "saved" })),
    workbenchAdd: vi.fn(async () => ({ bookmark_id: "B-1" })),
    workbenchRemove: vi.fn(async () => ({ status: "removed" })),
    getChallenge: vi.fn(async () => ({ challenge_id: "c", nonce: "n", salt: "s", iterations: 1 })),
    sealCase: vi.fn(async () => ({ status: "sealed" })),
  },
  chatStream: vi.fn(async () => undefined),
}));

vi.mock("../context/CaseContext", () => ({
  useCase: () => ({ mode: "1", activeCase: { id: "CASE-TEST" } }),
}));

vi.mock("react-router-dom", async () => {
  const actual = await vi.importActual<typeof import("react-router-dom")>("react-router-dom");
  return { ...actual, useNavigate: () => vi.fn() };
});

import SteerChat from "./SteerChat";

describe("SteerChat partial-answer badge", () => {
  it("renders the partial state for a persisted steer answer", async () => {
    render(
      <MemoryRouter>
        <SteerChat />
      </MemoryRouter>,
    );
    expect(await screen.findByText(/Partial answer/)).toBeTruthy();
  });
});
