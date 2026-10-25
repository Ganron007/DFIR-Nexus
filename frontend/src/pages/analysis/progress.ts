/**
 * One progress line per running mode (TA-9: the Analysis page showed only a status word). Built from the fields each
 * mode's status API already serves; a field the server did not send is left out, never shown as zero.
 */
import type { Mode2RunStatusResponse, Mode3RunStatus, PipelineStatusResponse } from "../../api/client";

function parts(...items: (string | false | undefined)[]): string {
  return items.filter((item): item is string => Boolean(item)).join(" · ");
}

function counted(n: number | undefined, word: string): string | undefined {
  return typeof n === "number" ? `${n} ${word}` : undefined;
}

/** Mode 1: the pipeline node it is in, and the tool lane's counters while that runs. */
export function mode1Progress(r: PipelineStatusResponse): string {
  const stages = r.stages ?? [];
  const node = [...stages].reverse().find((line) => line.stage);
  const lane = r.progress;
  return parts(
    node?.stage && `${node.stage}${node.status ? ` ${node.status}` : ""}`,
    lane && typeof lane.total === "number" && lane.total > 0 && `tools ${lane.done}/${lane.total}`,
    lane?.running?.tool && `running ${lane.running.tool}`,
  );
}

/** Mode 2: work orders finished (`order_index` counts finished orders, as `nexus mode2` prints it), follow-up
 *  rounds, and what the run has produced so far. */
export function mode2Progress(r: Mode2RunStatusResponse): string {
  const order =
    typeof r.orders === "number" && r.orders > 0 ? `${r.order_index ?? 0}/${r.orders} order(s) done` : undefined;
  const last = r.last_event;
  return parts(
    order,
    r.followup_rounds ? counted(r.followup_rounds, "follow-up round(s)") : undefined,
    counted(r.candidates, "candidate(s)"),
    counted(r.events, "event(s)"),
    last?.event_type && `last: ${last.event_type}${last.tool ? ` ${last.tool}` : ""}`,
  );
}

/** Mode 3: the superstep, the agents working now, and the board. */
export function mode3Progress(r: Mode3RunStatus): string {
  return parts(
    typeof r.superstep === "number" && `superstep ${r.superstep}`,
    counted(r.agents_running, "agent(s) working"),
    counted(r.board, "board item(s)"),
    counted(r.candidates, "candidate(s)"),
    r.disputes ? counted(r.disputes, "dispute(s)") : undefined,
  );
}
