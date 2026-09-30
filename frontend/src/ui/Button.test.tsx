import "@testing-library/jest-dom/vitest";
import { describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
import { Button } from "./Button";

describe("Button", () => {
  it("renders its label and handles clicks", () => {
    const onClick = vi.fn();
    render(<Button onClick={onClick}>Stage draft</Button>);
    fireEvent.click(screen.getByRole("button", { name: "Stage draft" }));
    expect(onClick).toHaveBeenCalledOnce();
  });

  it("loading disables the button and sets aria-busy", () => {
    render(
      <Button loading onClick={() => undefined}>
        Approve
      </Button>,
    );
    const button = screen.getByRole("button", { name: /approve/i });
    expect(button).toBeDisabled();
    expect(button).toHaveAttribute("aria-busy", "true");
  });

  it("does not fire clicks while loading", () => {
    const onClick = vi.fn();
    render(
      <Button loading onClick={onClick}>
        Approve
      </Button>,
    );
    fireEvent.click(screen.getByRole("button", { name: /approve/i }));
    expect(onClick).not.toHaveBeenCalled();
  });

  it("renders the danger variant with its accessible name intact", () => {
    render(
      <Button variant="danger">
        Reject <span>finding</span>
      </Button>,
    );
    expect(screen.getByRole("button", { name: /reject finding/i })).toBeInTheDocument();
  });
});
