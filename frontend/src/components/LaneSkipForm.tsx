/**
 * The examiner's audited lane skip (TA-9; `nexus lane skip` was the only way before). A skip clears the evidence gate
 * for the chosen unprocessed items: it is the examiner's decision, signed with the approval password through the same
 * HMAC challenge as finding approval, and it must say why. The password only derives the signature in this browser.
 */
import { useState } from "react";
import { api, type LaneGate, type LaneGateItem } from "../api/client";
import { computeApprovalResponse } from "../lib/crypto";
import { Button, Field, Input, Textarea } from "@/ui";
import styles from "./LaneSkipForm.module.css";

function itemKey(item: LaneGateItem): string {
  return `${item.tool ?? ""}\u0000${item.purpose ?? ""}`;
}

export default function LaneSkipForm({
  gate,
  onSkipped,
}: {
  gate: LaneGate;
  onSkipped: (gate: LaneGate) => void;
}) {
  const candidates = [...(gate.unprocessed ?? []), ...(gate.waiting_sift ?? [])];
  const [open, setOpen] = useState(false);
  const [chosen, setChosen] = useState<Set<string>>(() => new Set(candidates.map(itemKey)));
  const [reason, setReason] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState("");

  if (candidates.length === 0) return null;
  if (!open) {
    return (
      <Button size="sm" variant="ghost" onClick={() => setOpen(true)} data-testid="lane-skip-open">
        Record an examiner skip…
      </Button>
    );
  }

  const toggle = (key: string) =>
    setChosen((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });

  const submit = async () => {
    setError("");
    setResult("");
    if (chosen.size === 0) return setError("Choose at least one item to skip.");
    if (!reason.trim()) return setError("Say why: a skip is an examiner decision and is audited with its reason.");
    if (!password) return setError("The approval password is required to sign the skip.");
    setBusy(true);
    try {
      const ch = await api.getChallenge();
      const response = await computeApprovalResponse(password, ch.salt, ch.iterations, ch.nonce);
      const items = candidates
        .filter((item) => chosen.has(itemKey(item)))
        .map((item) => ({ tool: item.tool, purpose: item.purpose }));
      const r = await api.laneSkip({ challenge_id: ch.challenge_id, response, reason: reason.trim(), items });
      if (!r.ok) throw new Error(r.error || "The skip was refused.");
      setPassword("");
      setResult(`Recorded ${r.added ?? 0} skip(s). Gate: ${r.lane_gate?.status ?? "unknown"}.`);
      if (r.lane_gate) onSkipped(r.lane_gate);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <form
      className={styles.form}
      data-testid="lane-skip-form"
      onSubmit={(event) => {
        event.preventDefault();
        void submit();
      }}
    >
      <fieldset className={styles.items}>
        <legend>Items to skip</legend>
        {candidates.map((item) => {
          const key = itemKey(item);
          return (
            <label key={key} className={styles.item}>
              <input type="checkbox" checked={chosen.has(key)} onChange={() => toggle(key)} />{" "}
              <strong>{item.tool || "artifact"}</strong>
              {item.purpose ? ` - ${item.purpose}` : ""}
            </label>
          );
        })}
      </fieldset>
      <Field label="Reason" required hint="Recorded with your name in the gate and the case audit log.">
        {({ id, describedBy, invalid }) => (
          <Textarea
            id={id}
            aria-describedby={describedBy}
            invalid={invalid}
            rows={2}
            value={reason}
            onChange={(event) => setReason(event.target.value)}
          />
        )}
      </Field>
      <Field label="Approval password" required hint="Never sent: it only derives the HMAC signature here.">
        {({ id, describedBy, invalid }) => (
          <Input
            id={id}
            type="password"
            autoComplete="current-password"
            aria-describedby={describedBy}
            invalid={invalid}
            value={password}
            onChange={(event) => setPassword(event.target.value)}
          />
        )}
      </Field>
      {error && (
        <p role="alert" className={styles.error}>
          {error}
        </p>
      )}
      {result && <p className={styles.result}>{result}</p>}
      <div className={styles.actions}>
        <Button size="sm" variant="danger" type="submit" disabled={busy}>
          {busy ? "Signing…" : `Skip ${chosen.size} item(s)`}
        </Button>
        <Button size="sm" variant="ghost" type="button" onClick={() => setOpen(false)} disabled={busy}>
          Cancel
        </Button>
      </div>
    </form>
  );
}
