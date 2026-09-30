import "@testing-library/jest-dom/vitest";
import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import KitGallery from "./KitGallery";

describe("KitGallery", () => {
  it("renders the gallery with every kit section", () => {
    render(<KitGallery />);
    expect(screen.getByRole("heading", { name: "Kit gallery" })).toBeInTheDocument();
    for (const section of [
      "Buttons",
      "Overlays",
      "Data display",
      "Forms",
      "Status pills",
    ]) {
      expect(screen.getByRole("heading", { name: section })).toBeInTheDocument();
    }
  });

  it("renders one badge per semantic tone plus neutral", () => {
    render(<KitGallery />);
    const badges = screen.getAllByText(/^(sev|l1|verifier|origin|mode|seal|run|fresh)-/);
    expect(badges.length).toBeGreaterThanOrEqual(29);
    expect(screen.getByText("neutral")).toBeInTheDocument();
  });
});
