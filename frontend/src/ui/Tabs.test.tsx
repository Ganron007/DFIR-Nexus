import "@testing-library/jest-dom/vitest";
import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { Tabs } from "./Tabs";

const items = [
  { value: "lanes", label: "Lanes" },
  { value: "grid", label: "Grid" },
];

describe("Tabs", () => {
  it("exposes a named tablist with tab roles", () => {
    render(<Tabs items={items} value="lanes" onValueChange={() => undefined} label="Timeline views" />);
    const list = screen.getByRole("tablist", { name: "Timeline views" });
    expect(list).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: "Lanes" })).toHaveAttribute(
      "data-state",
      "active",
    );
    expect(screen.getByRole("tab", { name: "Grid" })).toHaveAttribute(
      "data-state",
      "inactive",
    );
  });

  it("is controlled — selecting a tab reports the value", async () => {
    const onValueChange = vi.fn();
    const user = userEvent.setup({ pointerEventsCheck: 0 });
    render(<Tabs items={items} value="lanes" onValueChange={onValueChange} label="views" />);
    await user.click(screen.getByRole("tab", { name: "Grid" }));
    expect(onValueChange).toHaveBeenCalledWith("grid");
  });

  it("marks disabled tabs", () => {
    render(
      <Tabs
        items={[...items, { value: "x", label: "Soon", disabled: true }]}
        value="lanes"
        onValueChange={() => undefined}
        label="views"
      />,
    );
    expect(screen.getByRole("tab", { name: "Soon" })).toBeDisabled();
  });
});
