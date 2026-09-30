import "@testing-library/jest-dom/vitest";
import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { Field, Input, Select, Textarea } from "./Field";

describe("Field", () => {
  it("wires the label, hint and control together", () => {
    render(
      <Field label="Case name" hint="Shown in the report header.">
        {({ id, describedBy, invalid }) => (
          <Input id={id} aria-describedby={describedBy} invalid={invalid} />
        )}
      </Field>,
    );
    const input = screen.getByLabelText("Case name");
    expect(input).toHaveAttribute("aria-describedby");
    expect(input.getAttribute("aria-describedby")).toMatch(/-hint$/);
    expect(input).not.toBeInvalid();
    expect(screen.getByText("Shown in the report header.")).toBeInTheDocument();
  });

  it("renders an error as an alert and marks the control invalid", () => {
    render(
      <Field label="Case name" error="A case name is required.">
        {({ id, describedBy, invalid }) => (
          <Input id={id} aria-describedby={describedBy} invalid={invalid} />
        )}
      </Field>,
    );
    const input = screen.getByLabelText("Case name");
    expect(input).toBeInvalid();
    expect(input.getAttribute("aria-describedby")).toMatch(/-error$/);
    expect(screen.getByRole("alert")).toHaveTextContent("A case name is required.");
  });

  it("supports select and textarea controls", () => {
    render(
      <>
        <Field label="Mode">
          {({ id }) => (
            <Select id={id}>
              <option>1 — LLM</option>
            </Select>
          )}
        </Field>
        <Field label="Question">
          {({ id }) => <Textarea id={id} />}
        </Field>
      </>,
    );
    expect(screen.getByRole("combobox", { name: "Mode" })).toBeInTheDocument();
    expect(screen.getByLabelText("Question")).toBeInTheDocument();
  });
});
