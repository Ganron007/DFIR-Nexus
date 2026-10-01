import { useMemo, useState } from "react";
import {
  Badge,
  Button,
  ConfirmDialog,
  CopyableHash,
  CopyablePath,
  DataGrid,
  Dialog,
  Drawer,
  EmptyState,
  Field,
  Input,
  KeyValue,
  PageHeader,
  Panel,
  Select,
  Skeleton,
  StatusPill,
  Tabs,
  Textarea,
  TimeAxis,
  TimeLanes,
  ToastProvider,
  useToast,
  type DataGridColumn,
  type GridQuery,
  type LaneSeries,
  type SemanticTone,
  type TimeRange,
} from "@/ui";
import { SEMANTIC_TONES } from "@/ui";
import styles from "./KitGallery.module.css";

const TONES = Object.keys(SEMANTIC_TONES) as SemanticTone[];

interface DemoRow {
  id: string;
  host: string;
  family: string;
  severity: string;
}

const DEMO_COLUMNS: DataGridColumn<DemoRow>[] = [
  {
    id: "id",
    header: "ID",
    accessorFn: (row) => row.id,
    filterable: true,
    pinnable: true,
    width: 160,
  },
  { id: "host", header: "Host", accessorFn: (row) => row.host, filterable: true, width: 160 },
  { id: "family", header: "Family", accessorFn: (row) => row.family, width: 140 },
  { id: "severity", header: "Severity", accessorFn: (row) => row.severity, width: 120 },
];

const DEMO_FAMILIES = ["evtx", "mft", "prefetch", "lnk", "registry", "browser", "tasks", "vss"];
const DEMO_SEVERITIES = ["LOW", "MEDIUM", "HIGH"];

/** 100k synthetic rows: the grid must stay smooth where a naive table dies. */
function demoRows(count: number): DemoRow[] {
  return Array.from({ length: count }, (_, i) => ({
    id: `F-${String(i + 1).padStart(6, "0")}`,
    host: `HOST-${String((i % 24) + 1).padStart(2, "0")}`,
    family: DEMO_FAMILIES[i % DEMO_FAMILIES.length],
    severity: DEMO_SEVERITIES[i % DEMO_SEVERITIES.length],
  }));
}

function TimeAxisDemo() {
  const [range, setRange] = useState<TimeRange>({
    start: new Date("2026-01-01T00:00:00Z"),
    end: new Date("2026-01-02T00:00:00Z"),
  });
  const lanes: LaneSeries[] = useMemo(
    () => [
      {
        id: "evtx",
        label: "evtx (a whole day)",
        buckets: [
          { t: Date.parse("2026-01-01T00:00:00Z"), count: 12 },
          { t: Date.parse("2026-01-01T12:00:00Z"), count: 48 },
          { t: Date.parse("2026-01-01T23:00:00Z"), count: 7 },
        ],
      },
      {
        id: "prefetch",
        label: "prefetch (three minutes)",
        buckets: [
          { t: Date.parse("2026-01-01T11:57:00Z"), count: 3 },
          { t: Date.parse("2026-01-01T12:00:00Z"), count: 9 },
        ],
      },
    ],
    [],
  );
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "var(--space-3)" }}>
      <TimeAxis
        range={range}
        width={720}
        histogram={[
          { t: Date.parse("2026-01-01T01:00:00Z"), count: 4 },
          { t: Date.parse("2026-01-01T06:00:00Z"), count: 9 },
          { t: Date.parse("2026-01-01T12:00:00Z"), count: 14 },
        ]}
        onRangeChange={setRange}
      />
      <TimeLanes lanes={lanes} range={range} width={720} onRangeChange={setRange} />
      <p style={{ fontFamily: "var(--font-mono)", fontSize: "var(--font-size-xs)" }}>
        {range.start.toISOString()} → {range.end.toISOString()}
      </p>
    </div>
  );
}

function DataGridDemo() {
  const [query, setQuery] = useState<GridQuery>({ filters: {}, sort: null });
  const [detail, setDetail] = useState<DemoRow | null>(null);
  const rows = useMemo(() => demoRows(100_000), []);
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "var(--space-3)" }}>
      <p style={{ fontFamily: "var(--font-mono)", fontSize: "var(--font-size-xs)" }}>
        query: {JSON.stringify(query)}
      </p>
      <DataGrid
        columns={DEMO_COLUMNS}
        rows={rows}
        getRowId={(row) => row.id}
        viewId="kit-gallery"
        onQueryChange={setQuery}
        onOpenRow={setDetail}
        ariaLabel="Kit gallery synthetic rows"
      />
      {detail ? (
        <p>
          opened <code>{detail.id}</code> on {detail.host} — the real page opens its
          detail Drawer here.
        </p>
      ) : null}
    </div>
  );
}

function ToastDemo() {
  const { push } = useToast();
  return (
    <Button
      onClick={() =>
        push({ title: "Saved", detail: "The draft was staged.", tone: "l1-proven" })
      }
    >
      Push a toast
    </Button>
  );
}

/**
 * Dev-only kit gallery (route /_kit, excluded from production builds).
 * Every kit component renders here; U9's visual-regression screenshots key
 * off this page.
 */
function Gallery() {
  const [tab, setTab] = useState("a");
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [dialogOpen, setDialogOpen] = useState(false);
  const [confirmOpen, setConfirmOpen] = useState(false);

  return (
    <div className={styles.page}>
      <PageHeader title="Kit gallery" subtitle="Dev-only — excluded from production builds" />

      <section className={styles.section}>
        <h2>Buttons</h2>
        <div className={styles.row}>
          <Button variant="primary">Primary</Button>
          <Button>Secondary</Button>
          <Button variant="danger">Danger</Button>
          <Button variant="ghost">Ghost</Button>
          <Button loading>Loading</Button>
          <Button size="sm">Small</Button>
        </div>
      </section>

      <section className={styles.section}>
        <h2>Semantic badges ({TONES.length} tones)</h2>
        <div className={styles.row}>
          {TONES.map((tone) => (
            <Badge key={tone} tone={tone}>
              {tone}
            </Badge>
          ))}
          <Badge>neutral</Badge>
        </div>
      </section>

      <section className={styles.section}>
        <h2>Status pills</h2>
        <div className={styles.row}>
          <StatusPill tone="run-running" label="Pipeline running" pulse />
          <StatusPill tone="run-complete" label="Complete" />
          <StatusPill tone="fresh-ok" label="Evidence verified" />
          <StatusPill tone="seal-broken" label="Seal broken" />
        </div>
      </section>

      <section className={styles.section}>
        <h2>Panels, header, tabs</h2>
        <Panel title="Indexed evidence" actions={<Button size="sm">Refresh</Button>}>
          <p>Panel body content.</p>
        </Panel>
        <Tabs
          label="Gallery tabs"
          items={[
            { value: "a", label: "Lane A" },
            { value: "b", label: "Lane B" },
          ]}
          value={tab}
          onValueChange={setTab}
        />
        <p aria-live="polite">Selected: {tab}</p>
      </section>

      <section className={styles.section}>
        <h2>Overlays</h2>
        <div className={styles.row}>
          <Button onClick={() => setDrawerOpen(true)}>Open drawer</Button>
          <Button onClick={() => setDialogOpen(true)}>Open dialog</Button>
          <Button variant="danger" onClick={() => setConfirmOpen(true)}>
            Confirm (danger)
          </Button>
          <ToastDemo />
        </div>
      </section>

      <section className={styles.section}>
        <h2>Data display</h2>
        <CopyableHash value="a3f1c9d77b4e2f8091acbd05e6624f3c8d9102ab77c4e5f6a1b2c3d4e5f60718" />
        <CopyablePath value="C:\\Users\\examiner\\Evidence-files\\01-windows\\evtx\\Security.evtx" />
        <KeyValue
          items={[
            { label: "Family", value: "evtx" },
            { label: "SHA-256", value: "a3f1c9d7…0718", mono: true },
          ]}
        />
        <Skeleton lines={3} />
        <EmptyState
          title="No findings staged"
          hint="Run the pipeline or promote a hit from the workbench."
          action={<Button variant="primary">Open briefing</Button>}
        />
        <EmptyState title="Query failed" tone="error" hint="Elasticsearch did not answer." />
      </section>

      <section className={styles.section}>
        <h2>Forms</h2>
        <Field label="Case name" required error="A case name is required.">
          {({ id, describedBy, invalid }) => (
            <Input id={id} aria-describedby={describedBy} invalid={invalid} />
          )}
        </Field>
        <Field label="Mode" hint="Default launcher mode for this case.">
          {({ id, describedBy }) => (
            <Select id={id} aria-describedby={describedBy}>
              <option>1 — LLM</option>
              <option>2 — multi-role</option>
              <option>3 — multi-agent</option>
            </Select>
          )}
        </Field>
        <Field label="Question">
          {({ id, describedBy }) => (
            <Textarea id={id} aria-describedby={describedBy} />
          )}
        </Field>
      </section>

      <section className={styles.section}>
        <h2>Time axis — two lanes, one UTC scale</h2>
        <TimeAxisDemo />
      </section>

      <section className={styles.section}>
        <h2>DataGrid — 100k rows, virtualised</h2>
        <DataGridDemo />
      </section>

      <Drawer open={drawerOpen} onOpenChange={setDrawerOpen} title="Finding detail">
        <p>Drawer body.</p>
      </Drawer>
      <Dialog open={dialogOpen} onOpenChange={setDialogOpen} title="Dialog">
        <p>Dialog body.</p>
      </Dialog>
      <ConfirmDialog
        open={confirmOpen}
        onOpenChange={setConfirmOpen}
        title="Reject finding?"
        body="The DRAFT stays in the case; the rejection is audited."
        confirmLabel="Reject"
        tone="danger"
        onConfirm={() => undefined}
      />
    </div>
  );
}

export default function KitGallery() {
  return (
    <ToastProvider>
      <Gallery />
    </ToastProvider>
  );
}
