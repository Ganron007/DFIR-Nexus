/**
 * Virtualized table component for rendering large datasets (100k+ rows).
 * Only renders rows visible in the scroll viewport.
 */

import { useRef, useState, useEffect, type ReactNode } from "react";

const ROW_HEIGHT = 28; // px per row
const OVERSCAN = 10; // extra rows above/below viewport

export interface Column<T> {
  key: string;
  header: string;
  width?: number;
  render: (row: T, index: number) => ReactNode;
}

interface VirtualTableProps<T> {
  rows: T[];
  columns: Column<T>[];
  rowKey: (row: T, index: number) => string;
  maxHeight?: string;
  onRowClick?: (row: T) => void;
}

export default function VirtualTable<T>({
  rows,
  columns,
  rowKey,
  maxHeight = "60vh",
  onRowClick,
}: VirtualTableProps<T>) {
  const scrollRef = useRef<HTMLDivElement>(null);
  const [scrollTop, setScrollTop] = useState(0);
  const [viewportHeight, setViewportHeight] = useState(600);

  useEffect(() => {
    const el = scrollRef.current;
    if (!el) return;
    const updateHeight = () => setViewportHeight(el.clientHeight);
    updateHeight();
    const ro = new ResizeObserver(updateHeight);
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  const startIndex = Math.max(0, Math.floor(scrollTop / ROW_HEIGHT) - OVERSCAN);
  const endIndex = Math.min(
    rows.length,
    Math.ceil((scrollTop + viewportHeight) / ROW_HEIGHT) + OVERSCAN,
  );
  const visibleRows = rows.slice(startIndex, endIndex);
  const offsetY = startIndex * ROW_HEIGHT;

  const handleScroll = (e: React.UIEvent<HTMLDivElement>) => {
    setScrollTop(e.currentTarget.scrollTop);
  };

  return (
    <div
      ref={scrollRef}
      onScroll={handleScroll}
      style={{
        maxHeight,
        overflowY: "auto",
        overflowX: "auto",
        position: "relative",
      }}
    >
      <table style={{ width: "100%", tableLayout: "fixed" }}>
        <thead>
          <tr>
            {columns.map((col) => (
              <th
                key={col.key}
                style={col.width ? { width: col.width } : undefined}
              >
                {col.header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {/* Spacer row for virtualization offset */}
          {startIndex > 0 && (
            <tr style={{ height: offsetY, padding: 0, border: "none" }}>
              <td colSpan={columns.length} style={{ padding: 0, border: "none" }} />
            </tr>
          )}
          {visibleRows.map((row, i) => {
            const index = startIndex + i;
            return (
              <tr
                key={rowKey(row, index)}
                onClick={onRowClick ? () => onRowClick(row) : undefined}
                style={onRowClick ? { cursor: "pointer" } : undefined}
              >
                {columns.map((col) => (
                  <td key={col.key}>{col.render(row, index)}</td>
                ))}
              </tr>
            );
          })}
          {/* Spacer row for remaining virtualized rows */}
          {endIndex < rows.length && (
            <tr
              style={{
                height: (rows.length - endIndex) * ROW_HEIGHT,
                padding: 0,
                border: "none",
              }}
            >
              <td colSpan={columns.length} style={{ padding: 0, border: "none" }} />
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
}
