# Insider Threat Matrix (investigator mapping)

Canonical framework: https://insiderthreatmatrix.org/

Use this taxonomy when interpreting host-triage evidence. Map each finding to
one primary **stage** and one or more **objects**. Do not invent Motive from
host artifacts alone — Motive is inferred only when Means/Preparation/
Infringement/Anti-Forensics objects are evidenced.

## Motive (why)

Boundary Testing · Coercion · Conflicts of Interest · Curiosity · Espionage ·
Fear of Reprisals · Hubris · Human Error · Ideology · Lack of Awareness ·
Leaver · Misapprehension or Delusion · Personal Gain · Political or
Philosophical Beliefs · Recklessness · Recognition · Resentment · Revenge ·
Rogue Nationalism · Self Sabotage · Third Party Collusion.

## Means (how they could)

Access · Credential Access and Exposure · Installed Software · Placement ·
Printing · Privileged Access · Removable Media · SMB File Sharing · Unrevoked
Access · Web Access · Clipboard · Corporate-Issued Device · FTP/SSH Servers.

## Preparation (setup)

Account Discovery · Archive Data · Circumventing Security Controls ·
Credential Collection · Data Obfuscation · Data Staging · Device Mounting ·
Email Collection · File Download · File Exploration · Lateral Movement ·
Privilege Elevation · Read Windows Registry · Remote Desktop (RDP) ·
Security Software Enumeration · Software Installation · Suspicious Web
Browsing · System Persistence · Testing Security Controls.

## Infringement (the harm)

Data Loss · Exfiltration via Email · Exfiltration via Messaging Applications ·
Exfiltration via Other Network Medium · Exfiltration via Physical Medium ·
Exfiltration via Web Service · Inappropriate Web Browsing · Installing
Unapproved Software · Theft · Unauthorized Account Access · Unauthorized
Changes to IT Systems.

## Anti-Forensics (cover-up)

Clear Browser Artifacts · Clear Email Artifacts · File Deletion · Hide
Artifacts · Hiding or Destroying Command History · Log Deletion · Log
Modification · Modify Windows Registry · Timestomping.

## Host-triage mapping (this lab)

| Artifact | Typical ITM objects |
|----------|---------------------|
| Failed/successful logons (EVTX/Hayabusa) | Means: Access, Credential Access; Preparation: Account Discovery, Testing Security Controls |
| Prefetch / Amcache / Shimcache | Means: Installed Software; Preparation: Software Installation, File Exploration |
| LNK / JumpLists / Shellbags | Preparation: File Exploration, Data Staging |
| SRUM network (OneDrive, browsers, cloud) | Means: Web Access; Infringement: Exfiltration via Web Service |
| Browser History (SQLite) | Preparation: Suspicious Web Browsing; Infringement: Exfiltration via Web Service |
| Recycle Bin | Anti-Forensics: File Deletion |
| Registry UserAssist / RecentDocs | Preparation: File Exploration |
| Memory pslist/cmdline | Means: Installed Software; Preparation: Privilege Elevation |
| Cloud-sync folders in LNKs | Preparation: Data Staging; Infringement: Exfiltration via Web Service |

Cite the Matrix URL on every mapped finding. If evidence is routine authorized
activity, say so and still map the object (Means/Preparation) at low confidence.
