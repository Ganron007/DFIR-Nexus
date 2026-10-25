/**
 * The examiner skip from the UI (TA-9): the same signed, reasoned, audited act as `nexus lane skip`. It never fires
 * without a reason and the password, and it sends exactly the items the examiner chose.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

vi.mock("../api/client", () => ({
  api: { getChallenge: vi.fn(), laneSkip: vi.fn() },
}));
vi.mock("../lib/crypto", () => ({
  computeApprovalResponse: vi.fn(),
}));

import { api } from "../api/client";
import { computeApprovalResponse } from "../lib/crypto";
import LaneSkipForm from "./LaneSkipForm";

const gate = {
  status: "blocked",
  run_id: "RUN-1",
  unprocessed: [
    { tool: "mftecmd", purpose: "NTFS metadata ($I30)", reason: "Command timed out after 240s" },
    { tool: "sbecmd", purpose: "ShellBags", reason: "hive is dirty" },
  ],
};

const mocked = <T,>(fn: T) => fn as unknown as ReturnType<typeof vi.fn>;

beforeEach(() => {
  vi.clearAllMocks();
  mocked(api.getChallenge).mockResolvedValue({
    challenge_id: "CH-1", nonce: "n1", salt: "s1", iterations: 600000, hash_algorithm: "sha256",
  });
  mocked(computeApprovalResponse).mockResolvedValue("hmac-hex");
});

async function openForm() {
  const user = userEvent.setup();
  const onSkipped = vi.fn();
  render(<LaneSkipForm gate={gate} onSkipped={onSkipped} />);
  await user.click(screen.getByTestId("lane-skip-open"));
  return { user, onSkipped };
}

describe("examiner lane skip form", () => {
  it("renders nothing when no item can be skipped", () => {
    const { container } = render(<LaneSkipForm gate={{ status: "blocked", unprocessed: [] }} onSkipped={vi.fn()} />);
    expect(container.textContent).toBe("");
  });

  it("refuses to sign without a reason and the password", async () => {
    const { user } = await openForm();
    await user.click(screen.getByRole("button", { name: /Skip 2 item/ }));
    expect(screen.getByRole("alert").textContent).toMatch(/Say why/);
    await user.type(screen.getByLabelText(/Reason/), "no hive logs exist for this host");
    await user.click(screen.getByRole("button", { name: /Skip 2 item/ }));
    expect(screen.getByRole("alert").textContent).toMatch(/password is required/);
    expect(api.getChallenge).not.toHaveBeenCalled();
    expect(api.laneSkip).not.toHaveBeenCalled();
  });

  it("signs the challenge and sends only the chosen items with the reason", async () => {
    const cleared = { status: "clear", run_id: "RUN-1", examiner_skips: [{ tool: "sbecmd", purpose: "ShellBags" }] };
    mocked(api.laneSkip).mockResolvedValue({ ok: true, added: 1, lane_gate: cleared });
    const { user, onSkipped } = await openForm();
    await user.click(screen.getByLabelText(/mftecmd/));
    await user.type(screen.getByLabelText(/Reason/), "  no hive logs exist for this host ");
    await user.type(screen.getByLabelText(/Approval password/), "pw");
    await user.click(screen.getByRole("button", { name: /Skip 1 item/ }));

    expect(computeApprovalResponse).toHaveBeenCalledWith("pw", "s1", 600000, "n1");
    expect(api.laneSkip).toHaveBeenCalledWith({
      challenge_id: "CH-1",
      response: "hmac-hex",
      reason: "no hive logs exist for this host",
      items: [{ tool: "sbecmd", purpose: "ShellBags" }],
    });
    expect(onSkipped).toHaveBeenCalledWith(cleared);
    expect(screen.getByText(/Recorded 1 skip\(s\)\. Gate: clear\./)).toBeTruthy();
    expect((screen.getByLabelText(/Approval password/) as HTMLInputElement).value).toBe("");
  });

  it("shows the server's refusal and leaves the gate alone", async () => {
    mocked(api.laneSkip).mockRejectedValue(new Error("Incorrect password. 2 attempt(s) remaining."));
    const { user, onSkipped } = await openForm();
    await user.type(screen.getByLabelText(/Reason/), "reason");
    await user.type(screen.getByLabelText(/Approval password/), "wrong");
    await user.click(screen.getByRole("button", { name: /Skip 2 item/ }));
    expect(screen.getByRole("alert").textContent).toMatch(/Incorrect password/);
    expect(onSkipped).not.toHaveBeenCalled();
  });
});
