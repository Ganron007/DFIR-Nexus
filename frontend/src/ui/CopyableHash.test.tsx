import "@testing-library/jest-dom/vitest";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
import { CopyableHash } from "./CopyableHash";

const HASH =
  "a3f1c9d77b4e2f8091acbd05e6624f3c8d9102ab77c4e5f6a1b2c3d4e5f60718";

const writeText = vi.fn<(text: string) => Promise<void>>(async () => undefined);

beforeEach(() => {
  writeText.mockClear();
  Object.defineProperty(navigator, "clipboard", {
    value: { writeText },
    configurable: true,
  });
});

describe("CopyableHash", () => {
  it("shows a 12-char prefix with the full hash available to copy", async () => {
    render(<CopyableHash value={HASH} />);
    const button = screen.getByRole("button", { name: `Copy hash ${HASH.slice(0, 12)}` });
    expect(button).toHaveTextContent(HASH.slice(0, 12));
    expect(button.textContent).not.toContain(HASH.slice(13, 20));
    fireEvent.click(button);
    await vi.waitFor(() => {
      expect(writeText).toHaveBeenCalledWith(HASH);
    });
  });

  it("shows a short value in full", () => {
    render(<CopyableHash value="abc123" />);
    expect(
      screen.getByRole("button", { name: "Copy hash abc123" }),
    ).toHaveTextContent("abc123");
  });
});
