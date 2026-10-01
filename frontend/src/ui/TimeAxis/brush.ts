/**
 * Brush hook (WO-U6 / WP 14.6): drag emits an EXACT UTC range.
 *
 * "Exact" is the point. The old timeline brush snapped to hour-bucket indices,
 * so a brush over a 3-minute incident returned a whole hour and the event panel
 * then showed everything in it. This brush converts pixels through the same
 * shared scale the lanes draw with, so what the examiner selects is the range
 * they see - no snapping, no rounding.
 *
 * Mouse events, not pointer events: they are what a drag produces everywhere
 * and what the tests can drive without a layout engine.
 */
import { useCallback, useRef, useState, type MouseEvent as ReactMouseEvent } from "react";

import type { UtcScale } from "./scale";
import type { TimeRange } from "./types";

export interface BrushState {
  x0: number;
  x1: number;
}

export interface BrushOptions {
  scale: UtcScale;
  width: number;
  onRangeChange?: (range: TimeRange) => void;
  onBrushPreview?: (range: TimeRange | null) => void;
}

export function useBrush(options: BrushOptions): {
  brush: BrushState | null;
  handlers: {
    onMouseDown: (event: ReactMouseEvent<SVGSVGElement>) => void;
    onMouseMove: (event: ReactMouseEvent<SVGSVGElement>) => void;
    onMouseUp: (event: ReactMouseEvent<SVGSVGElement>) => void;
  };
} {
  const { scale, width, onRangeChange, onBrushPreview } = options;
  const [brush, setBrush] = useState<BrushState | null>(null);
  const anchorRef = useRef<number | null>(null);

  const localX = useCallback(
    (event: ReactMouseEvent<SVGSVGElement>) => {
      const rect = event.currentTarget.getBoundingClientRect();
      const left = rect && rect.width ? rect.left : 0;
      return Math.min(width, Math.max(0, event.clientX - left));
    },
    [width],
  );

  const onMouseDown = useCallback(
    (event: ReactMouseEvent<SVGSVGElement>) => {
      const x = localX(event);
      anchorRef.current = x;
      setBrush({ x0: x, x1: x });
    },
    [localX],
  );

  const onMouseMove = useCallback(
    (event: ReactMouseEvent<SVGSVGElement>) => {
      const anchor = anchorRef.current;
      if (anchor === null) return;
      const x = localX(event);
      const next = { x0: Math.min(anchor, x), x1: Math.max(anchor, x) };
      setBrush(next);
      onBrushPreview?.({ start: scale.invert(next.x0), end: scale.invert(next.x1) });
    },
    [localX, onBrushPreview, scale],
  );

  const onMouseUp = useCallback(
    (event: ReactMouseEvent<SVGSVGElement>) => {
      const anchor = anchorRef.current;
      if (anchor === null) return;
      anchorRef.current = null;
      const x = localX(event);
      const next = { x0: Math.min(anchor, x), x1: Math.max(anchor, x) };
      setBrush(null);
      onBrushPreview?.(null);
      // a click (not a drag) is not a range
      if (next.x1 - next.x0 < 1) return;
      onRangeChange?.({ start: scale.invert(next.x0), end: scale.invert(next.x1) });
    },
    [localX, onRangeChange, onBrushPreview, scale],
  );

  return { brush, handlers: { onMouseDown, onMouseMove, onMouseUp } };
}