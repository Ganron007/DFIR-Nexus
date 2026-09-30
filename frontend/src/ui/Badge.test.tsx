import "@testing-library/jest-dom/vitest";
import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { Badge } from "./Badge";
import { SEMANTIC_TONES } from "./semantic";

describe("Badge", () => {
  it("renders children with the neutral look when no tone is given", () => {
    render(<Badge>neutral badge</Badge>);
    expect(screen.getByText("neutral badge")).toBeInTheDocument();
  });

  it("binds a semantic tone through the registry, never a raw colour", () => {
    render(<Badge tone="l1-proven">PROVEN</Badge>);
    const badge = screen.getByText("PROVEN");
    expect(badge).toHaveAttribute("data-tone", "l1-proven");
    expect(badge.getAttribute("style")).toContain(SEMANTIC_TONES["l1-proven"]);
  });

  it("exposes every semantic tone name as renderable", () => {
    const tones = Object.keys(SEMANTIC_TONES);
    expect(tones.length).toBeGreaterThanOrEqual(29);
    for (const tone of tones) {
      render(<Badge tone={tone as keyof typeof SEMANTIC_TONES}>{tone}</Badge>);
      expect(screen.getByText(tone)).toHaveAttribute("data-tone", tone);
    }
  });
});
