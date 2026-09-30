import "@testing-library/jest-dom/vitest";
import { describe, expect, it } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
import { ToastProvider, useToast } from "./Toast";

function Pusher() {
  const { push } = useToast();
  return (
    <button
      type="button"
      onClick={() =>
        push({ title: "Draft staged", detail: "F-001 saved.", tone: "l1-proven" })
      }
    >
      push
    </button>
  );
}

describe("Toast", () => {
  it("pushes a toast with title and detail", () => {
    render(
      <ToastProvider>
        <Pusher />
      </ToastProvider>,
    );
    fireEvent.click(screen.getByRole("button", { name: "push" }));
    expect(screen.getByText("Draft staged")).toBeInTheDocument();
    expect(screen.getByText("F-001 saved.")).toBeInTheDocument();
  });

  it("dismisses a toast from its close button", () => {
    render(
      <ToastProvider>
        <Pusher />
      </ToastProvider>,
    );
    fireEvent.click(screen.getByRole("button", { name: "push" }));
    expect(screen.getByText("Draft staged")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Dismiss" }));
    expect(screen.queryByText("Draft staged")).toBeNull();
  });
});
