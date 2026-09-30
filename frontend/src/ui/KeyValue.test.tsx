import "@testing-library/jest-dom/vitest";
import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { KeyValue } from "./KeyValue";

describe("KeyValue", () => {
  it("renders label/value pairs as a definition list", () => {
    render(
      <KeyValue
        items={[
          { label: "Family", value: "evtx" },
          { label: "SHA-256", value: "a3f1c9d7…0718", mono: true },
        ]}
      />,
    );
    expect(screen.getByText("Family")).toBeInTheDocument();
    expect(screen.getByText("evtx")).toBeInTheDocument();
    const hash = screen.getByText("a3f1c9d7…0718");
    expect(hash.className).toMatch(/mono/i);
  });
});
