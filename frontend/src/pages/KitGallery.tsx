import { useState } from "react";
import {
  Badge,
  Button,
  ConfirmDialog,
  CopyableHash,
  CopyablePath,
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
  ToastProvider,
  useToast,
  type SemanticTone,
} from "@/ui";
import { SEMANTIC_TONES } from "@/ui";
import styles from "./KitGallery.module.css";

const TONES = Object.keys(SEMANTIC_TONES) as SemanticTone[];

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
