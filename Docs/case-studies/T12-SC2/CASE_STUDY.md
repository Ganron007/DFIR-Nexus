# Case Study SC2: Multi-Stage Windows Active Directory Enterprise Intrusion (T12)

**Case ID:** `CASE-7FA5756A`  
**Dataset Reference:** Tiny Case T12 (Group C, Format F)  
**Evidence Scope:** 11 Windows Event Log (`.evtx`) artifacts (3.9 MB)  
**License:** Creative Commons Zero (CC0 1.0 Universal — Public Domain Dedication)  
**Investigation Platform:** DFIR-Nexus (v1 Pre-Release, Mode 1/2/3 Cockpit)  
**Examiner Reviewer:** `claudebot` / Examiner Cockpit  
**Date Generated:** 2026-11-12  

---

## 1. Executive Summary

This published case study demonstrates the full DFIR-Nexus investigation lifecycle on a publicly distributable, simulated Windows Active Directory enterprise intrusion dataset (T12). The incident captures a sophisticated multi-stage campaign spanning initial C2 implant installation, credential dumping via DCSync, rogue domain controller registration (CVE-2021-42287 / DCShadow), lateral movement via PsExec and SMB, and subsequent impact attempts via Hermetic Wiper tradecraft.

The complete evidence processing, multi-mode investigation, examiner cross-examination, and reporting pipeline was executed cleanly under strict forensic discipline:
- **Index Integrity:** 2,122 documents indexed into Elasticsearch with **0 errors**, **0 rejections**, and **0 dropped fields** (satisfying Defect Register D147).
- **Multi-Mode Execution:** Triaged across Mode 1 (deterministic hypothesis generation), Mode 2 (autonomous LLM investigation director), and Mode 3 (deliberative multi-agent cross-examination).
- **Examiner Governance:** All 22 staged draft findings were formally reviewed against the L1 case index:
  - **17 Findings Approved** (100% L1-PROVEN) with cryptographic HMAC entries committed to the tamper-evident verification ledger.
  - **5 Findings Rejected** (L1 UNVERIFIABLE / UNSUPPORTED) with documented examiner rationale qualifying the raw observations while rejecting uncorroborated causal inferences.
- **Reporting:** Formal DFIR report (`REPORT.md`) generated from approved findings, evidence tables, and chronological event reconstruction.

---

## 2. Dataset Provenance & Identifier Sanitization

### 2.1 Provenance & License
- **Origin:** Publicly released DFIR training dataset simulating an Active Directory enterprise intrusion.
- **License:** Dedicated to the public domain under **Creative Commons Zero (CC0 1.0 Universal)**. Freely redistributable for research, benchmarking, and education without proprietary licensing restrictions.

### 2.2 Identifier and Privacy Audit
Per the DFIR-Nexus publication standard and egress filtering rules (D146 / D497):
- **Domain Identity:** Synthetic training domain `offsec.lan` (`DC=offsec,DC=lan`).
- **Asset Identifiers:** Virtualized lab hosts:
  - `srvdefender01.offsec.lan` (Initial C2 implant / service installation)
  - `rootdc1.offsec.lan` (Primary Active Directory Domain Controller)
  - `fs03vuln.offsec.lan` (File server target of lateral movement and PsExec)
  - `jump01.offsec.lan` / `fs01.offsec.lan` (Staging jump box and auxiliary storage)
- **Account Identifiers:** Synthetic domain user accounts (`OFFSEC\admmig`, `LOCAL SYSTEM`, `Administrator`).
- **Network Addressing:** Loopback (`127.0.0.1`) and RFC 1918 private lab addressing only.
- **PII & Secrets:** Verified free of confidential customer records, cleartext proprietary credentials, or external sensitive telemetry.

---

## 3. Tool Lane & Ingestion Metrics

Evidence ingestion was performed via the DFIR-Nexus evidentiary tool lane:
- **Parsers:**
  - `EvtxECmd` (Eric Zimmerman tools): Parsed 1,054 structured event records into `extractions/evtxecmd/`.
  - `Hayabusa` (Yamato Security): Generated 1,068 timeline alerts and technique detections into `extractions/hayabusa/`.
  - `Chainsaw` (Sigma rule matching): Opt-in Sigma detections into `extractions/chainsaw/`.
- **Elasticsearch Ingestion (`es_index.json`):**
  - Index Name: `nexus-case-case-7fa5756a`
  - Total Documents: **2,122**
  - Ingestion Errors: **0**
  - Unindexed Fields / Values: **0**
  - Dynamic EventData Keys: Bounded, adhering to schema constraints without truncation.

---

## 4. Key Attack Phases & Findings Summary

The investigation reconstructed five distinct attack phases:

```
[Phase 1: Initial C2 Foothold]
  └── srvdefender01: Service 'iOWamcEn' installed with encoded PowerShell payload (F-claudebot-138, F-claudebot-186)
[Phase 2: Local Discovery & Preparation]
  └── srvdefender01: Rapid secedit /export commands collecting security configuration (F-claudebot-147)
[Phase 3: Domain Compromise & Credential Theft]
  ├── rootdc1: Non-machine account 'admmig' initiates DS replication / DCSync (F-claudebot-190, F-claudebot-231)
  └── rootdc1: Rogue DC machine account masquerading via CVE-2021-42287 & Event 4781 (F-claudebot-192, F-claudebot-230)
[Phase 4: Lateral Movement & Persistence]
  ├── fs03vuln: NTLM network logons and SMB pass-the-hash authentication (F-claudebot-139, F-claudebot-187)
  └── fs03vuln: PsExec64 execution from C:\TOOLS\ launching PSEXESVC as SYSTEM (F-claudebot-191, F-claudebot-232)
[Phase 5: Defense Evasion & Anti-Forensics]
  ├── fs03vuln & srvdefender01: Security Event Log 1102 clearing (F-claudebot-144, F-claudebot-188, F-claudebot-229)
  └── srvdefender01: Output redirection to loopback ADMIN$ share (F-claudebot-143, F-claudebot-189)
```

### 4.1 Approved Findings (17 Findings)
All 17 approved findings were verified by the L1 claim verifier as mathematically proven by indexed evidence rows:
1. `F-claudebot-138` (Critical): Encoded PowerShell implant installed as Windows service on `srvdefender01`.
2. `F-claudebot-139` (High): Matching process command encodings across multiple hosts.
3. `F-claudebot-143` (Critical): Process command redirection to loopback `ADMIN$` share.
4. `F-claudebot-144` (High): Security Event Log clearing (Event ID 1102).
5. `F-claudebot-145` (High): NTLM network authentication patterns consistent with Pass-the-Hash.
6. `F-claudebot-147` (Medium): Execution of `secedit.exe /export` commands on `srvdefender01`.
7. `F-claudebot-186` (Critical): Service `iOWamcEn` demand-start configuration and execution telemetry.
8. `F-claudebot-187` (High): SMB NTLM Type-3 authentication to `fs03vuln`.
9. `F-claudebot-188` (High): Event log clearing telemetry on `fs03vuln` and `srvdefender01`.
10. `F-claudebot-189` (Critical): Loopback administrative share redirection behavior.
11. `F-claudebot-190` (Critical): Active Directory replication object access on `rootdc1`.
12. `F-claudebot-191` (Critical): PsExec service execution (`PSEXESVC`) as `LOCAL SYSTEM`.
13. `F-claudebot-192` (Critical): Rogue domain controller account modification (Event 4781).
14. `F-claudebot-229` (High): Confirmed Event 1102 log-clearing timestamps.
15. `F-claudebot-230` (Critical): Detailed sAMAccountName machine account anomalies on `rootdc1`.
16. `F-claudebot-231` (Critical): DCSync replication indicators with specific property GUIDs.
17. `F-claudebot-232` (Critical): Detailed command-line and pipe telemetry for `PsExec64.exe`.

### 4.2 Rejected Drafts & Examiner Discipline (5 Findings)
In accordance with forensic discipline rules (FD-001..007) and examiner recommendations in `examiner_review.md`, 5 draft findings failed L1 verification and were formally rejected:
- `F-claudebot-140` (PsExec remote arrival claim): *Rejected.* The evidence confirms local `PSEXESVC` execution, but does not prove remote arrival vector or same-second file chronology.
- `F-claudebot-141` (DCShadow exploitation assertion): *Rejected.* Confirms AD object access alerts, but does not prove completed domain-wide secret theft or successful rogue DC promotion.
- `F-claudebot-142` (WMI DCOM remote lateral movement claim): *Rejected.* Loopback `127.0.0.1` access does not establish remote DCOM network transport or external exfiltration.
- `F-claudebot-146` (Metasploit binary delivery assertion): *Rejected (Failing L1.7).* Concrete NTLM fields are retained, but unverified client-supplied workstation strings do not substantiate external Metasploit binary delivery.
- `F-claudebot-148` (Staging exfiltration narrative): *Rejected.* Confirms local share access checks, but does not prove stolen payload staging or sustained attacker capability.

---

## 5. Artifacts and Associated Files

- **Official IR Report:** [`REPORT.md`](file:///c:/STUDY/Github/CADRE-Platform/DFIR-Nexus/Docs/case-studies/T12-SC2/REPORT.md)
- **Source Case Directory:** `cases/CASE-7FA5756A/`
- **Case Digest & Provenance:** `cases/CASE-7FA5756A/analysis/case_digest.json`
- **Examiner Review Record:** `cases/CASE-7FA5756A/analysis/examiner_review.md`
- **Verification Ledger:** `~/.nexus/verification/CASE-7FA5756A.jsonl`
