import "@testing-library/jest-dom/vitest";
import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { Button } from "./Button";
import { Panel } from "./Panel";

describe("Panel", () => {
  it("renders title, actions and body", () => {
    render(
      <Panel title="Indexed evidence" actions={<Button size="sm">Refresh</Button>}>
        <p>128,213 docs</p>
      </Panel>,
    );
    expect(screen.getByRole("heading", { name: "Indexed evidence" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Refresh" })).toBeInTheDocument();
    expect(screen.getByText("128,213 docs")).toBeInTheDocument();
  });

  it("renders a body-only panel without a header", () => {
    render(
      <Panel>
        <p>plain</p>
      </Panel>,
    );
    expect(screen.getByText("plain")).toBeInTheDocument();
    expect(screen.queryByRole("heading")).toBeNull();
  });
});
