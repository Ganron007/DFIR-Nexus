import { describe, expect, it } from "vitest";
import { render } from "@testing-library/react";
import { Skeleton } from "./Skeleton";

describe("Skeleton", () => {
  it("renders the requested number of lines, hidden from AT", () => {
    const { container } = render(<Skeleton lines={4} />);
    const root = container.firstElementChild as HTMLElement;
    expect(root.getAttribute("aria-hidden")).toBe("true");
    expect(root.children.length).toBe(4);
  });

  it("defaults to three lines", () => {
    const { container } = render(<Skeleton />);
    expect((container.firstElementChild as HTMLElement).children.length).toBe(3);
  });
});
