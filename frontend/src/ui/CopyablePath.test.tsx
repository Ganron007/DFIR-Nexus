import "@testing-library/jest-dom/vitest";
import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { CopyablePath, middleEllipsis } from "./CopyablePath";

describe("middleEllipsis", () => {
  it("leaves short paths untouched", () => {
    expect(middleEllipsis("C:\\cases\\Security.evtx")).toBe(
      "C:\\cases\\Security.evtx",
    );
  });

  it("keeps both ends and the extension visible on long paths", () => {
    const long = "C:\\Users\\examiner\\Evidence-files\\01-windows\\evtx\\Security.evtx";
    const short = middleEllipsis(long, 40);
    expect(short.length).toBeLessThanOrEqual(41);
    expect(short).toContain("…");
    expect(short.startsWith("C:\\Users")).toBe(true);
    expect(short.endsWith("Security.evtx")).toBe(true);
  });
});

describe("CopyablePath", () => {
  it("renders the copy affordance named after the full path", () => {
    render(<CopyablePath value={"C:\\cases\\Security.evtx"} />);
    expect(
      screen.getByRole("button", { name: "Copy path C:\\cases\\Security.evtx" }),
    ).toBeInTheDocument();
  });
});
