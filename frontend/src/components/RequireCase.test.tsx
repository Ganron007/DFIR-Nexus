/**
 * Phase 4e.4: cockpit route guard.
 *
 * No active case -> redirect to the dashboard; while booting -> placeholder
 * (never a premature redirect); with an active case -> children render.
 */
import { describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import { MemoryRouter, Routes, Route } from "react-router-dom";

const { mockUseCase } = vi.hoisted(() => ({ mockUseCase: vi.fn() }));

vi.mock("../context/CaseContext", () => ({
  useCase: mockUseCase,
}));

import RequireCase from "./RequireCase";

function renderGuard(state: Record<string, unknown>) {
  mockUseCase.mockReturnValue(state);
  return render(
    <MemoryRouter initialEntries={["/explore"]}>
      <Routes>
        <Route path="/" element={<div>dashboard-page</div>} />
        <Route
          path="/explore"
          element={
            <RequireCase>
              <div>cockpit-page</div>
            </RequireCase>
          }
        />
      </Routes>
    </MemoryRouter>,
  );
}

describe("RequireCase", () => {
  it("redirects to the dashboard when no case is active", () => {
    renderGuard({ booting: false, activeCase: "" });
    expect(screen.getByText("dashboard-page")).toBeTruthy();
    expect(screen.queryByText("cockpit-page")).toBeNull();
  });

  it("renders children when a case is active", () => {
    renderGuard({ booting: false, activeCase: "CASE-1" });
    expect(screen.getByText("cockpit-page")).toBeTruthy();
  });

  it("shows a placeholder while booting (no premature redirect)", () => {
    renderGuard({ booting: true, activeCase: "" });
    expect(screen.getByText(/Loading case/i)).toBeTruthy();
    expect(screen.queryByText("dashboard-page")).toBeNull();
  });

  it("renders an alert instead of swallowing errors when route case activation fails", async () => {
    const setActiveCase = vi.fn().mockRejectedValue(new Error("403 forbidden"));
    mockUseCase.mockReturnValue({
      booting: false,
      activeCase: "CASE-1",
      cases: ["CASE-1", "CASE-2"],
      setActiveCase,
    });
    render(
      <MemoryRouter initialEntries={["/cases/CASE-2/explore"]}>
        <Routes>
          <Route path="/" element={<div>dashboard-page</div>} />
          <Route
            path="/cases/:caseId/explore"
            element={
              <RequireCase>
                <div>cockpit-page</div>
              </RequireCase>
            }
          />
        </Routes>
      </MemoryRouter>,
    );
    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toContain("403 forbidden");
    expect(screen.queryByText("cockpit-page")).toBeNull();
  });
});
