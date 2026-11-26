/**
 * Approval Desk accessibility and form label bindings.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";

const { mockFindings, mockCommitStatus } = vi.hoisted(() => ({
  mockFindings: vi.fn(),
  mockCommitStatus: vi.fn(),
}));

vi.mock("../api/client", () => ({
  api: {
    findings: mockFindings,
    commitStatus: mockCommitStatus,
    getChallenge: vi.fn(),
    commit: vi.fn(),
    reject: vi.fn(),
  },
}));

vi.mock("../context/CaseContext", () => ({
  useCase: () => ({
    activeCase: "CASE-APPROVE-1",
    refreshStages: vi.fn(),
  }),
}));

import Approve from "./Approve";

describe("Approve page labels", () => {
  beforeEach(() => {
    mockFindings.mockResolvedValue({
      findings: [
        {
          id: "F-001",
          title: "Suspicious scheduled task",
          observation: "Observed task creation",
          interpretation: "Persistence candidate",
          confidence: "MEDIUM",
          status: "DRAFT",
          l1: { verdict: "UNVERIFIABLE" },
        },
      ],
    });
    mockCommitStatus.mockResolvedValue({
      examiner: "alice",
      password_configured: true,
      setup_hint: "nexus config --setup-password",
    });
  });

  it("associates visible labels with inputs for Examiner Identity, Approval Password, Override Reason, and Rejection Reason", async () => {
    render(
      <MemoryRouter>
        <Approve />
      </MemoryRouter>,
    );

    const examinerInput = await screen.findByLabelText(/Examiner Identity/i);
    const passwordInput = screen.getByLabelText(/Approval Password/i);
    const overrideInput = screen.getByLabelText(/Override Reason/i);

    expect(examinerInput.tagName).toBe("INPUT");
    expect(passwordInput.getAttribute("type")).toBe("password");
    expect(overrideInput.tagName).toBe("INPUT");

    fireEvent.click(screen.getByRole("button", { name: /Reject/i }));
    const rejectInput = screen.getByLabelText(/Reason for Rejection/i);
    expect(rejectInput.tagName).toBe("INPUT");
  });
});
