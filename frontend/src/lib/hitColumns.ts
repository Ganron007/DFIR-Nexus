/**
 * WP 4d.1 shared: per-family priority fields for type-aware hit rendering.
 * Used by Explore and the Timeline event panel.
 *
 * The backend attaches `fields` (parsed CSV header -> value) to every hit;
 * these lists pick which parsed columns to surface first. Unknown families
 * fall back to GENERIC_FIELD_PRIORITY, and any parser output still renders
 * via its actual CSV headers.
 */
import type { N4Hit } from "../api/client";

export const FAMILY_FIELD_PRIORITY: Record<string, string[]> = {
  evtx: ["TimeCreated", "EventID", "Computer", "Channel", "Level", "Message"],
  security: ["TimeCreated", "EventID", "Computer", "TargetUserName", "SubjectUserName", "IpAddress"],
  system: ["TimeCreated", "EventID", "Computer", "Provider", "Message"],
  powershell: ["TimeCreated", "ScriptBlockText", "Path", "Message"],
  pecmd: ["ExecutableName", "RunCount", "LastRun", "SourceFile"],
  prefetch: ["ExecutableName", "RunCount", "LastRun", "SourceFile"],
  amcache: ["Name", "Path", "SHA1", "FirstSeen", "LastSeen"],
  appcompat: ["Path", "LastModified", "Size"],
  appcompatcacheparser: ["Path", "LastModified"],
  shellbags: ["Path", "LastWriteTime", "SourceFile"],
  lnk: ["LocalPath", "Arguments", "WorkingDirectory", "TargetCreated"],
  jlecmd: ["SourceFile", "EntryName", "LastAccessed"],
  jumplist: ["SourceFile", "EntryName", "LastAccessed"],
  recmd: ["FileName", "OriginalPath", "DeletedFrom"],
  recycle: ["OriginalPath", "DeletedFrom", "DeletionTime"],
  rbcmd: ["OriginalFileName", "DeletedFrom", "DeletionTime"],
  mftecmd: ["FileName", "ParentPath", "Created0x10", "LastModified0x10"],
  mft: ["FileName", "ParentPath", "Created", "Modified"],
  srum: ["AppName", "UserId", "TimeStamp", "BytesSent", "BytesRecvd"],
  hayabusa: ["Timestamp", "RuleTitle", "Level", "Computer", "EventID"],
  usn: ["FileName", "UpdateReason", "Timestamp"],
  browser: ["URL", "Title", "VisitCount", "LastVisitTime"],
  chrome: ["URL", "Title", "VisitCount", "LastVisitTime"],
  edge: ["URL", "Title", "VisitCount", "LastVisitTime"],
  registry: ["KeyPath", "ValueName", "Value", "LastWriteTime"],
  scheduled_tasks: ["TaskName", "Action", "Author"],
  services: ["Name", "ImagePath", "StartMode"],
  userassist: ["Name", "RunCount", "LastExecution"],
  usb: ["Device", "SerialNumber", "FirstInstall", "LastConnect"],
  setupapi: ["Device", "Serial", "FirstInstall"],
};

export const GENERIC_FIELD_PRIORITY = [
  "TimeCreated", "Timestamp", "EventID", "Computer", "Name", "Path", "URL",
  "ExecutableName", "FileName", "LastWriteTime", "Message",
];

/** Pick up to 4 parsed columns to render for a set of hits. */
export function pickHitColumns(hits: N4Hit[]): string[] {
  const tally: Record<string, number> = {};
  for (const h of hits) {
    const f = h.family || "other";
    tally[f] = (tally[f] || 0) + 1;
  }
  const dominant = Object.entries(tally).sort((a, b) => b[1] - a[1])[0]?.[0] || "";
  const priority = FAMILY_FIELD_PRIORITY[dominant] || GENERIC_FIELD_PRIORITY;
  const present = new Set<string>();
  for (const h of hits) {
    for (const k of Object.keys(h.fields || {})) present.add(k);
  }
  const chosen = priority.filter((f) => present.has(f)).slice(0, 4);
  if (chosen.length === 0) {
    for (const f of present) {
      chosen.push(f);
      if (chosen.length >= 4) break;
    }
  }
  return chosen;
}
