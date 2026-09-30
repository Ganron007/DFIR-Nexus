import "@testing-library/jest-dom/vitest";
import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { StatusPill } from "./StatusPill";

describe("StatusPill", () => {
  it("renders dot and label", () => {
    render(<StatusPill tone="run-running" label="Pipeline running" pulse />);
    const pill = screen.getByText("Pipeline running");
    expect(pill).toHaveAttribute("data-tone", "run-running");
    expect(pill.querySelector("span[aria-hidden='true']")).not.toBeNull();
  });

  it("marks running states as live regions the examiner can find", () => {
    render(<StatusPill tone="fresh-stale" label="Evidence stale" />);
    expect(screen.getByText("Evidence stale")).toBeInTheDocument();
  });
});
