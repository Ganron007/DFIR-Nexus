import "@testing-library/jest-dom/vitest";
import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { TimeAxis } from "./TimeAxis";
import { TimeLanes } from "./TimeLanes";
import { createUtcScale, formatForSpan, parseUtc, zoomRange } from "./scale";
import type { LaneSeries, TimeRange } from "./types";

const DAY_START = new Date("2026-01-01T00:00:00.000Z");
const DAY_END = new Date("2026-01-02T00:00:00.000Z");
const DAY: TimeRange = { start: DAY_START, end: DAY_END };

const at = (iso: string) => new Date(iso).getTime();

const LANES: LaneSeries[] = [
  {
    id: "evtx",
    label: "evtx",
    buckets: [
      { t: at("2026-01-01T00:00:00Z"), count: 10 },
      { t: at("2026-01-01T12:00:00Z"), count: 40 },
    ],
  },
  {
    // a lane whose own data covers three minutes - the case the per-card scale
    // got wrong
    id: "prefetch",
    label: "prefetch",
    buckets: [
      { t: at("2026-01-01T11:57:00Z"), count: 3 },
      { t: at("2026-01-01T12:00:00Z"), count: 8 },
    ],
  },
];

describe("scale", () => {
  it("maps the range onto the width, in UTC", () => {
    const scale = createUtcScale(DAY, 800);
    expect(scale(DAY_START)).toBe(0);
    expect(scale(DAY_END)).toBe(800);
    expect(scale(new Date("2026-01-01T12:00:00Z"))).toBe(400);
    expect(scale.invert(400)?.toISOString()).toBe("2026-01-01T12:00:00.000Z");
  });

  it("picks a tick format by span", () => {
    expect(formatForSpan(30_000)).toBe("%H:%M:%S");
    expect(formatForSpan(60 * 60_000)).toBe("%H:%M");
    expect(formatForSpan(36 * 60 * 60_000)).toBe("%m-%d %H:%M");
    expect(formatForSpan(30 * 24 * 60 * 60_000)).toBe("%Y-%m-%d");
  });

  it("reads bare hour buckets as UTC, not local time", () => {
    expect(parseUtc("2026-01-01T13")?.toISOString()).toBe("2026-01-01T13:00:00.000Z");
    expect(parseUtc("2026-01-01T13:00:00Z")?.toISOString()).toBe("2026-01-01T13:00:00.000Z");
    expect(parseUtc("nonsense")).toBeNull();
    expect(parseUtc(null)).toBeNull();
  });

  it("zooms around the middle and never below a second", () => {
    const zoomed = zoomRange(DAY, 0.5);
    expect(zoomed.end.getTime() - zoomed.start.getTime()).toBe(12 * 60 * 60_000);
    // the anchor (midday) stays put while the span halves
    expect(zoomed.start.getTime() + 6 * 60 * 60_000).toBe(DAY_START.getTime() + 12 * 60 * 60_000);
    const out = zoomRange(DAY, 2);
    expect(out.end.getTime() - out.start.getTime()).toBe(48 * 60 * 60_000);
    const tiny = zoomRange({ start: DAY_START, end: new Date(DAY_START.getTime() + 2) }, 0.5);
    expect(tiny.end.getTime() - tiny.start.getTime()).toBeGreaterThanOrEqual(1000);
  });
});

describe("TimeAxis", () => {
  it("renders UTC ticks", () => {
    render(<TimeAxis range={DAY} width={800} tickCount={4} />);
    const labels = screen.getAllByTestId("tick").map((el) => el.textContent?.trim() ?? "");
    expect(labels.length).toBeGreaterThan(1);
    // a one-day span labels with dates, and the labels are UTC wall time
    expect(labels.every((l) => /^\d{2}-\d{2} \d{2}:\d{2}$/.test(l))).toBe(true);
    expect(labels.some((l) => l.startsWith("01-01"))).toBe(true);
  });

  it("brushes an exact range with no snapping", () => {
    const onRangeChange = vi.fn();
    render(<TimeAxis range={DAY} width={800} onRangeChange={onRangeChange} />);
    const svg = screen.getByTestId("time-axis-svg");

    fireEvent.mouseDown(svg, { clientX: 200 });
    fireEvent.mouseMove(svg, { clientX: 400 });
    fireEvent.mouseUp(svg, { clientX: 400 });

    expect(onRangeChange).toHaveBeenCalledTimes(1);
    const range = onRangeChange.mock.calls[0][0] as TimeRange;
    // 200px..400px of an 800px day is 06:00Z..12:00Z exactly
    expect(range.start.toISOString()).toBe("2026-01-01T06:00:00.000Z");
    expect(range.end.toISOString()).toBe("2026-01-01T12:00:00.000Z");
  });

  it("treats a click as no range at all", () => {
    const onRangeChange = vi.fn();
    render(<TimeAxis range={DAY} width={800} onRangeChange={onRangeChange} />);
    const svg = screen.getByTestId("time-axis-svg");
    fireEvent.mouseDown(svg, { clientX: 300 });
    fireEvent.mouseUp(svg, { clientX: 300 });
    expect(onRangeChange).not.toHaveBeenCalled();
  });

  it("zooms in and out through the range callback", () => {
    const onRangeChange = vi.fn();
    render(<TimeAxis range={DAY} width={800} onRangeChange={onRangeChange} />);
    fireEvent.click(screen.getByTestId("zoom-in"));
    const zoomed = onRangeChange.mock.calls[0][0] as TimeRange;
    expect(zoomed.end.getTime() - zoomed.start.getTime()).toBe(12 * 60 * 60_000);
    fireEvent.click(screen.getByTestId("zoom-out"));
    const out = onRangeChange.mock.calls[1][0] as TimeRange;
    expect(out.end.getTime() - out.start.getTime()).toBe(48 * 60 * 60_000);
  });

  it("draws the histogram lane under the axis", () => {
    render(
      <TimeAxis
        range={DAY}
        width={800}
        histogram={[
          { t: at("2026-01-01T01:00:00Z"), count: 5 },
          { t: at("2026-01-01T05:00:00Z"), count: 9 },
        ]}
      />,
    );
    expect(screen.getAllByTestId("histogram-bar")).toHaveLength(2);
  });
});

describe("TimeLanes", () => {
  it("puts two lanes with different spans on one shared scale", () => {
    render(<TimeLanes lanes={LANES} range={DAY} width={800} laneHeight={30} />);

    const noon = String(at("2026-01-01T12:00:00Z"));
    const xFor = (id: string) => {
      const lane = screen.getByTestId(`lane-${id}`);
      const mark = lane.querySelector(`[data-t="${noon}"]`);
      return Number(mark?.getAttribute("x"));
    };

    // the same instant lands on the same pixel in both lanes, whatever each
    // lane's own span is (the evtx lane spans a day, prefetch three minutes)
    expect(xFor("evtx")).toBe(xFor("prefetch"));
    // midday on an 800px day sits at 400; marks are centred, hence half a bar
    expect(Math.abs(xFor("evtx") - 400)).toBeLessThanOrEqual(2);
  });

  it("brushes one range for the whole stack", () => {
    const onRangeChange = vi.fn();
    render(
      <TimeLanes lanes={LANES} range={DAY} width={800} onRangeChange={onRangeChange} />,
    );
    const svg = screen.getByTestId("time-lanes-svg");
    fireEvent.mouseDown(svg, { clientX: 0 });
    fireEvent.mouseUp(svg, { clientX: 200 });
    const range = onRangeChange.mock.calls[0][0] as TimeRange;
    expect(range.start.toISOString()).toBe("2026-01-01T00:00:00.000Z");
    expect(range.end.toISOString()).toBe("2026-01-01T06:00:00.000Z");
  });

  it("reports the selected lane", () => {
    const onSelectLane = vi.fn();
    render(
      <TimeLanes
        lanes={LANES}
        range={DAY}
        width={800}
        onSelectLane={onSelectLane}
        selectedLaneId="evtx"
      />,
    );
    fireEvent.click(screen.getByTestId("lane-prefetch"));
    expect(onSelectLane).toHaveBeenCalledWith("prefetch");
    expect(screen.getByTestId("lane-evtx")).toHaveAttribute("data-selected", "true");
  });
});