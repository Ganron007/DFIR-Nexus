import "@testing-library/jest-dom/vitest";
import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { Button } from "./Button";
import { EmptyState } from "./EmptyState";

describe("EmptyState", () => {
  it("renders title, hint and action", () => {
    render(
      <EmptyState
        title="No findings staged"
        hint="Run the pipeline or promote a hit."
        action={<Button variant="primary">Open briefing</Button>}
      />,
    );
    expect(screen.getByRole("status")).toBeInTheDocument();
    expect(screen.getByText("No findings staged")).toBeInTheDocument();
    expect(screen.getByText("Run the pipeline or promote a hit.")).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Open briefing" }),
    ).toBeInTheDocument();
  });

  it("renders the error tone for failed queries", () => {
    render(<EmptyState title="Query failed" tone="error" />);
    expect(screen.getByText("Query failed")).toBeInTheDocument();
  });
});
