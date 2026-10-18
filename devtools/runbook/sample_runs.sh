#!/usr/bin/env bash
# Fresh, independent Mode 1, 2 and 3 runs on one case, one after the other (TIER1-WORK-ORDERS Part 10, P3).
# Each run's model calls are traced (devtools/trace_prompts.py) and kept under its run id; nothing is approved here.
#   bash devtools/runbook/sample_runs.sh CASE-ID TAG [MODES]      e.g.  ... CASE-0D525078 S01 "1 2 3"
# Logs:   cases/<CASE>/.trace/run-<TAG>-mode<N>.log      Run ids: cases/<CASE>/.trace/runs-<TAG>.ids
# Traces: cases/<CASE>/.trace/model_calls-<RUN_ID>.jsonl
set -u
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
CASE="$1"; TAG="$2"; MODES="${3:-1 2 3}"
TRACE="$REPO/cases/$CASE/.trace"
RUNS_DIR="$REPO/cases/$CASE/runs"
cd "$REPO" || exit 1
mkdir -p "$TRACE"
# A lane's SIFT settings must not leak into an analysis run.
unset NEXUS_SIFT_MCP_URL NEXUS_WINDOWS_MCP_URL NEXUS_SIFT_EVIDENCE_ROOT NEXUS_SIFT_ZEEK
export PYTHONUNBUFFERED=1 PYTHONIOENCODING=utf-8
RUNS="$TRACE/runs-$TAG.ids"

interpret_runs() { ls -d "$RUNS_DIR"/RUN-*-interpret-* 2>/dev/null | xargs -r -n1 basename | sort; }

run_mode() {
  local mode="$1" pattern="$2"
  local log="$TRACE/run-$TAG-mode$mode.log"
  local before
  before="$(interpret_runs)"
  # A trace left by an interrupted run is kept apart, never counted as this run's calls.
  if [ -f "$TRACE/model_calls.jsonl" ]; then
    mv "$TRACE/model_calls.jsonl" "$TRACE/model_calls-orphan-$(date -u +%Y%m%dT%H%M%SZ).jsonl"
  fi
  date -u +%FT%TZ > "$log"
  echo "HEAD $(git rev-parse --short HEAD)" >> "$log"
  python devtools/trace_prompts.py --case "$CASE" --mode "$mode" -- --context independent >> "$log" 2>&1
  echo "MODE${mode}_EXIT=$?" >> "$log"
  date -u +%FT%TZ >> "$log"
  local rid=""
  if [ "$mode" = "1" ]; then
    # `nexus interpret` prints run_id=<id> (D290); a build before it did not, so the run folder it made is the fallback.
    rid="$(grep -o 'run_id=RUN-[^ ]*' "$log" | tail -1 | cut -d= -f2)"
    [ -n "$rid" ] || rid="$(comm -13 <(echo "$before") <(interpret_runs) | tail -1)"
  else
    rid="$(grep -o "$pattern" "$log" | tail -1)"
  fi
  echo "mode$mode $rid" >> "$RUNS"
  if [ -n "$rid" ] && [ -f "$TRACE/model_calls.jsonl" ]; then
    mv "$TRACE/model_calls.jsonl" "$TRACE/model_calls-$rid.jsonl"
    echo "TRACE=$TRACE/model_calls-$rid.jsonl" >> "$log"
  fi
}

for m in $MODES; do
  case "$m" in
    1) run_mode 1 '' ;;
    2) run_mode 2 'M2-[0-9]\{8\}T[0-9]\{6\}-[0-9a-f]\{6\}' ;;
    3) run_mode 3 'M3-[0-9]\{8\}T[0-9]\{6\}-[0-9a-f]\{6\}' ;;
  esac
done
echo "SAMPLE_RUNS_DONE $TAG $(awk '{print $2}' "$RUNS" | tr '\n' ' ')"
