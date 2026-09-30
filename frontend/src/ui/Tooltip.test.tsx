import "@testing-library/jest-dom/vitest";
import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { Tooltip } from "./Tooltip";

describe("Tooltip", () => {
  it("shows the content on hover and hides it again on leave", async () => {
    const user = userEvent.setup({ pointerEventsCheck: 0 });
    render(
      <Tooltip content="a3f1c9d77b4e…0718">
        <button type="button">hash</button>
      </Tooltip>,
    );
    await user.hover(screen.getByRole("button", { name: "hash" }));
    expect(await screen.findByRole("tooltip")).toHaveTextContent("a3f1c9d77b4e…0718");
    // Radix closes the tooltip on Escape and on real pointer transit; jsdom
    // does not run the pointer-transit path, so Escape is the jsdom signal
    // (pointer-leave close is covered by the U9 browser e2e).
    await user.keyboard("{Escape}");
    await vi.waitFor(() => {
      expect(screen.queryByRole("tooltip")).toBeNull();
    });
  });
});
