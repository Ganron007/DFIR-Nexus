import "@testing-library/jest-dom/vitest";
import { describe, expect, it, vi } from "vitest";
import { useState } from "react";
import { fireEvent, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { Drawer } from "./Drawer";

describe("Drawer", () => {
  it("renders nothing when closed", () => {
    render(
      <Drawer open={false} onOpenChange={() => undefined} title="Finding detail">
        <p>body</p>
      </Drawer>,
    );
    expect(screen.queryByRole("dialog")).toBeNull();
  });

  it("opens with an accessible title and closes on Escape", async () => {
    const onOpenChange = vi.fn();
    const user = userEvent.setup();
    render(
      <Drawer open onOpenChange={onOpenChange} title="Finding detail">
        <p>body</p>
      </Drawer>,
    );
    const dialog = screen.getByRole("dialog");
    expect(dialog).toHaveAccessibleName("Finding detail");
    await user.keyboard("{Escape}");
    expect(onOpenChange).toHaveBeenCalledWith(false);
  });

  it("moves focus into the dialog on open; Escape closes", async () => {
    // Focus return to the trigger is Radix behaviour verified in a real
    // browser (U9 keyboard e2e); jsdom does not run Radix's unmount restore.
    const user = userEvent.setup();
    function Scenario() {
      const [open, setOpen] = useState(false);
      return (
        <>
          <button type="button" onClick={() => setOpen(true)}>
            Open detail
          </button>
          <Drawer open={open} onOpenChange={setOpen} title="Detail">
            <p>body</p>
          </Drawer>
        </>
      );
    }
    render(<Scenario />);
    await user.click(screen.getByRole("button", { name: "Open detail" }));
    const dialog = screen.getByRole("dialog");
    await vi.waitFor(() => {
      expect(dialog.contains(document.activeElement)).toBe(true);
    });
    await user.keyboard("{Escape}");
    expect(screen.queryByRole("dialog")).toBeNull();
  });

  it("fires onOpenChange(false) when the close button is used", () => {
    const onOpenChange = vi.fn();
    render(
      <Drawer open onOpenChange={onOpenChange} title="Detail">
        <p>body</p>
      </Drawer>,
    );
    fireEvent.click(screen.getByRole("button", { name: "Close" }));
    expect(onOpenChange).toHaveBeenCalledWith(false);
  });
});
