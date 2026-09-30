import "@testing-library/jest-dom/vitest";
import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { PageHeader } from "./PageHeader";

describe("PageHeader", () => {
  it("renders title, subtitle, stage badge and actions", () => {
    render(
      <PageHeader
        title="Evidence"
        subtitle="Registered artifacts and custody"
        stageCode="N2"
        actions={<button type="button">Register</button>}
      />,
    );
    expect(screen.getByRole("heading", { name: /Evidence/ })).toBeInTheDocument();
    expect(screen.getByText("N2")).toBeInTheDocument();
    expect(screen.getByText("Registered artifacts and custody")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Register" })).toBeInTheDocument();
  });

  it("omits the stage badge when no stage code is given", () => {
    render(<PageHeader title="Overview" />);
    expect(screen.getByRole("heading", { name: "Overview" })).toBeInTheDocument();
  });
});
