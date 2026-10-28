## The `findevil` forensic directory

**IMPORTANT NOTE! - FindEvil is work in progress. FindEvil will miss certain types of malware while quickly locating others. FindEvil only detects user-mode malware. FindEvil have false positives in its current implementation. FindEvil is primarily available on 64-bit Windows 10 and 11**

The directory _findevil_ exists as a sub-directory to the forensic directory at _/forensic/findevil_. To active findevil and scan for indicators of evil forensic mode must be activated.

FindEvil locates signs of malware by analyzing select indicators of evil. FindEvil swiftly discovers certain code injection techniques commonly employed by malware while it is completely unaware of other not-yet implemented indicators.

FindEvil makes use of built-in [Yara rules from Elastic](https://github.com/elastic/protections-artifacts) for select functionality. To enable the rules the Elastic License 2.0 must be accepted first with start-up option: [`-license-accept-elastic-license-2-0`](https://github.com/ufrisk/MemProcFS-dev/wiki/_CommandLine#-license-accept-elastic-license-2-0).

The files in the **findevil** directories are listed in the table below:
| File                 | Description                                                                  |
| -------------------- | ---------------------------------------------------------------------------- |
| findevil.txt         | Result file with possible detections of evil.                                |
| readme.txt           | README file.                                                                 |
| yara.txt             | Detailed information about YR_* detections. ´                                |
| yara_rules.txt       | YARA rules that triggered triggered detections.                              |

Files in the _findevil_ directory is read-only.

### Description of `findevil.txt`

```
#       PID Process         Type        VirtualAddress   ModuleName
=======================================================================
0000   2188 spoolsv.exe     PE_INJECT   0000000001840000 ext_server_priv.x64.dll
0001    356 SecurityHealth  PE_NOLINK   00007ffd700d0000 AppCore.dll
0002    356 SecurityHealth  PE_NOLINK   00007ffd702d0000 Windows.Storage.dll
0003    356 SecurityHealth  PE_NOLINK   00007ffd71ad0000 Wldp.dll

...

#       PID Process         Type        VirtualAddress    PhysicalAddr              PTE Flags      VADVirtAddr  VadPhysAddr           VadPTE VadFlagsType   VadName
=============================================================================================================================================================================
04ef   1192 svchost.exe     PE_PATCHED  00007ffd723f2000  000000123000 0000000000123157 A rwx ffffbe8e75a83930 000070dee000 0a00000070dee121 A Image ---wxc \Windows\System32\msvcp_win.dll
04f0   1192 svchost.exe     PE_PATCHED  00007ffd723fe000  000054686000 0000000054686477 A rwx ffffbe8e75a83930 000003ce1000 0a00000003ce1121 A Image ---wxc \Windows\System32\msvcp_win.dll
04f1   5392 MicrosoftEdgeC  PE_PATCHED  00007ffd6f69d000  0000510af000 02000000510af005 A r-x ffffbe8e7a2341c0 00006f097000 8a0000006f097121 A Image ---wxc ndows\System32\CoreMessaging.dll
04f2   5392 MicrosoftEdgeC  PE_PATCHED  00007ffd6f6a0000  00005119c000 020000005119c005 A r-x ffffbe8e7a2341c0 00006f098000 8a0000006f098121 A Image ---wxc ndows\System32\CoreMessaging.dll                   
04fa   2188 spoolsv.exe     PRIVATE_RWX 0000000001840000  0000131a8000 08000000131a8867 A rwx ffffbe8e77e690b0 000000000000 0000000000000000 -       p-rwx-
04fb   2188 spoolsv.exe     PRIVATE_RWX 0000000001841000  000031629000 0800000031629867 A rwx ffffbe8e77e690b0 000000000000 0000000000000000 -       p-rwx-
04fc   2188 spoolsv.exe     PRIVATE_RWX 0000000001842000  00005f9aa000 080000005f9aa867 A rwx ffffbe8e77e690b0 000000000000 0000000000000000 -       p-rwx-
04fd   2188 spoolsv.exe     PRIVATE_RWX 0000000001843000  00001ffab000 080000001ffab867 A rwx ffffbe8e77e690b0 000000000000 0000000000000000 -       p-rwx-
0508   4312 svchost.exe     PRIVATE_RX  00000139cfe07000  000000000000 0000000000000015 A r-x ffffbe8e79f0a4c0 000000000000 0000000000000000 -       p-rw--
0509   1172 svchost.exe     NOIMAGE_RX  00007ff502202000  000000f00000 0000000000f00745 A r-x ffffbe8e7a1028a0 000000000000 0000000000000000 -       ------
```



### Example

The example below shows the global _forensic/findevil/findevil.txt_ and with indications of a cobalt strike infection in the svchost, powershell and rundll32 processes. Please note that it may take a few seconds to render the _findevil.txt_ listing asynchronously from first folder access.

[[resources/root_findevil.png]]



### Indicators of Evil
Indicators of Evil are generally sorted by likelyhood and severeness. Some indicators are only reported a certain number of times before being suppressed.

| `YR_*`                | Yara based detections                     |
| --------------------- | ----------------------------------------- |
| Description:          | YR_* are potential evils flagged by Yara scanning. See additional information for each scanning type. |
| False&nbsp;Positives: | MEDIUM: Yara rules are usually high-quality, but false positives exists. |
| Other:                | Yara rules are mostly based on [Elastic Security rules](https://github.com/elastic/protections-artifacts/tree/main/yara/rules). Rules are disabled unless license is accepted.<br/>To enable, the [Elastic License 2.0 License agreement](https://www.elastic.co/licensing/elastic-license) must be accepted with command line option: `-license-accept-elastic-license-2-0` |

<details><summary>Additional Information:</summary>

| Type                  | Description                               |
| --------------------- | ----------------------------------------- |
| `YR_TROJAN`           |                                           |
| `YR_VULNDRIVER`       | Known vulnerable driver. Often used for evil, but not malicious in itself. |
| `YR_HACKTOOL`         | Often used for offensive purposes, may be used in security audits as well. |
| `YR_EXPLOIT`          |                                           |
| `YR_SHELLCODE`        |                                           |
| `YR_ROOTKIT`          |                                           |
| `YR_RANSOMWARE`       |                                           |
| `YR_WIPER`            |                                           |
| `YR_BACKDOOR`         | Often legit remote management software, but often used for evil. |
| `YR_GENERIC`          | Other classes of Yara rules.             |

</details>

---

| `AV_DETECT`           | Anti-Virus Detection        |
| --------------------- | --------------------------- |
| Description:          | AV_DETECT reports malware detected by the anti-virus residing on the analyzed system. |
| False&nbsp;Positives: | LOW                         |

---

| `PE_INJECT`           | Injected Modules            |
| --------------------- | --------------------------- |
| Description:          | PE_INJECT locates malware by scanning for valid .DLLs and .EXEs with executable pages in their page tables located in a private (non-image) virtual address descriptor. |
| False&nbsp;Positives: | LOW |
| Side Effects:         | Injected modules are loaded into the general module map and may be accessed as [files](https://github.com/ufrisk/MemProcFS/wiki/FS_Process_Files) and [modules](https://github.com/ufrisk/MemProcFS/wiki/FS_Process_Modules). |

---

| `PEB_MASQ`            | PEB Masquerading                          |
| --------------------- | ----------------------------------------- |
| Description:          | PEB_MASQ will flag PEB Masquerading attempts. If PEB_MASQ is detected please investigate further in /sys/proc/proc-v.txt |
| False&nbsp;Positives: | LOW                                       |
| Side Effects:         | PE_NOLINK findings are suppressed.        |

---

| `PE_HDR_SPOOF`        | Module PE header may be spoofed.          |
| --------------------- | ----------------------------------------- |
| Description:          | PE_HDR_SPOOF - Module PE header employs a known spoof technique. |
| False&nbsp;Positives: | LOW: May trigger on valid PE headers using one of the detected spoof techniques for legit reasons. |

<details><summary>Additional Information:</summary>

Detects [Low Alignment PE files](https://secret.club/2023/06/05/spoof-pe-sections.html) - i.e. PE files in which everything is mapped into a single section overriding any section headers.

</details>

---

| `PEB_BAD_LDR`         | No Modules enumerated from PEB/LDR_DATA |
| --------------------- | ----------------------------------------- |
| Description:          | BAD_PEB_LDR will flag if no in-process modules are enumerated from the PEB/LDR_DATA structures. |
| False&nbsp;Positives: | HIGH : Often trigger on corrupt PEB/LDR_DATA memory for non-malware reasons - such as paged out or otherwise unavailable memory; or drift during memory acquisition. |
| Side Effects:         | PE_NOLINK findings are suppressed.        |

---

| `PROC_BAD_DTB`        | Invalid process DirectoryTableBase (DTB)  |
| --------------------- | ----------------------------------------- |
| Description:          | PROC_BAD_DTB will flag active processes with an invalid DirectoryTableBase (DTB) in the kernel _EPROCESS object. |
| False&nbsp;Positives: | HIGH: May trigger on corrupt memory as well as malware activities. |

<details><summary>Additional Information:</summary>

In the case of a maliciously modified DirectoryTableBase/DTB/CR3 it may be possible to recover it manually.

This is done by looking at potential DTBs without any related process in the file `dtb.txt` in the [`/misc/procinfo/`](./FS_Misc_ProcInfo) module. If such entries are found they can be tested by writing them to the `dtb.txt` in the process root folder. This is likely to be some trial and error involved and is not something MemProcFS will do automatically.

</details>

---

| `PROC_BASEADDR`       | Process base address mismatch             |
| --------------------- | ----------------------------------------- |
| Description:          | PROC_BASEADDR is an indication or process hollowing. Flags if the PEB.ImageBaseAddress does not match EPROCESS.SectionBaseAddress. |
| False&nbsp;Positives: | MEDIUM: Relatively few false positives, but may trigger on legit processes. |

---

| `PROC_NOLINK`         | Module not found in EPROCESS linked list  |
| --------------------- | ----------------------------------------- |
| Description:          | PROC_NOLINK will flag if the process does not exist in the kernel _EPROCESS linked list. |
| False&nbsp;Positives: | MEDIUM: May trigger on slightly corrupt memory as well as malware activities. |

---

| `PROC_PARENT`         | Well known process has bad parent process |
| --------------------- | ----------------------------------------- |
| Description:          | PROC_PARENT will flag if a well known process has a bad parent process. |
| False&nbsp;Positives: | MEDIUM: May trigger if another process has the same name as a well known process. |

---

| `PROC_USER`           | Process is executing as non standard user |
| --------------------- | ----------------------------------------- |
| Description:          | PROC_USER may trigger if well known processes are executing as a strange user. Example cmd.exe as SYSTEM. |
| False&nbsp;Positives: | MEDIUM: May trigger if another process has the same name as a well known process. |

---

| `PROC_DEBUG`          | Processes with the SeDebugPrivilege       |
| --------------------- | ----------------------------------------- |
| Description:          | PROC_DEBUG flag non-SYSTEM processes with the SeDebugPrivilege. |
| False&nbsp;Positives: | MEDIUM: Also triggers on legit applications with the SeDebugPrivilege. |

---

| `THREAD`              | Thread based detections.                  |
| --------------------- | ----------------------------------------- |
| Description:          | THREAD flag various thread related issues. Detections are listed below.<br>`NO_IMAGE`: Thread not started in image memory. <br>`PRIVATE_MEMORY`: Thread started in private memory. <br>`BAD_MODULE`: Thread started in module without legit entry point. <br>`LOAD_LIBRARY`: Thread starting point is kernel32.dll!LoadLibrary. <br>`SYSTEM_IMPERSONATION`: Thread impersonates SYSTEM. <br>`NO_RTLUSERTHREADSTART`: Thread startup is not RtlUserThreadStart. |
| False&nbsp;Positives: | HIGH: Often flag legit SYSTEM_IMPERSONATION. Thread start at LOAD_LIBRARY is sometimes used by legit products. |

---

| `TIME_CHANGE`         | System Time Change          |
| --------------------- | --------------------------- |
| Description:          | TIME_CHANGE reports a system time change backwards in time to a time before the boot time. A system time change is not malicious in itself but may provide important context. |
| False&nbsp;Positives: | LOW                         |

---

| `PE_NOLINK`           | Unlinked Modules            |
| --------------------- | --------------------------- |
| Description:          | PE_NOLINK locates malware in image virtual address descriptors which is not linked from the in-process PEB/Ldr lists. |
| False&nbsp;Positives: | HIGH : Often trigger on corrupt memory for non-malware reasons - such as paged out or otherwise unavailable memory; or drift during memory acquisition. |

---

| `PE_PATCHED`          | Patched Modules             |
| --------------------- | --------------------------- |
| Description:          | PE_PATCHED locates malware in image virtual address descriptors which executable pages (in the page tables) differs from kernel prototype memory. |
| False&nbsp;Positives: | HIGH : Commonly triggers on relocations predominantly in 32-bit processes. Number of pages reported is limited to 4 per VAD. |

---

| `DRIVER_PATH`         | Kernel driver loaded from non-standard path |
| --------------------- | ------------------------------------------- |
| Description:          | DRIVER_PATH flag kernel drivers that are loaded from a non-standard path. DRIVER_PATH also flag if no corresponding module could be located. |
| False&nbsp;Positives: | MEDIUM : Legit drivers aren't usually loaded from non-standard paths - but they exist. Missing modules may flag on corrupt memory. |

---

| `PRIVATE_RWX`         | Private Read/Write/Execute  |
| --------------------- | --------------------------- |
| Description:          | PRIVATE_RWX locates malware with read/write/execute (RWX) pages in the page table which belongs to a private memory virtual address descriptor. |
| False&nbsp;Positives: | MEDIUM : RWX memory should be relatively rare on most systems; but in some processes with Just-In-Time code (JIT) it may be common. Number of pages reported is limited to 4 per VAD. Detection is avoided on some processes.  |

---

| `NOIMAGE_RWX`         | No-Image Read/Write/Execute |
| --------------------- | --------------------------- |
| Description:          | NOIMAGE_RWX locates malware with read/write/execute (RWX) pages in the page table which does not belong to image (module) virtual address descriptors. |
| False&nbsp;Positives: | MEDIUM : RWX memory should be relatively rare on most systems; but in some processes with Just-In-Time code (JIT) it may be common. Number of pages reported is limited to 4 per VAD. Detection is avoided on some processes.  |

<hr>

| `PRIVATE_RX`          | Private Read/Execute        |
| --------------------- | --------------------------- |
| Description:          | PRIVATE_RX locates malware with read/execute (RX) pages in the page table which belongs to a private memory virtual address descriptor. |
| False&nbsp;Positives: | MEDIUM : RX memory should be relatively rare on most systems; but in some processes with Just-In-Time code (JIT) it may be common. Number of pages reported is limited to 4 per VAD. Detection is avoided on some processes.  |

---

| `NOIMAGE_RX`          | No-Image Read/Execute       |
| --------------------- | --------------------------- |
| Description:          | NOIMAGE_RX locates malware with read/execute (RX) pages in the page table which does not belong to image (module) virtual address descriptors. |
| False&nbsp;Positives: | MEDIUM : RX memory should be relatively rare on most systems; but in some processes with Just-In-Time code (JIT) it may be common. Number of pages reported is limited to 4 per VAD. Detection is avoided on some processes.  |

---

| `UM_APC`              | User-Mode APC hook                        |
| --------------------- | ----------------------------------------- |
| Description:          | UM_APC locates an APC hook - commonly used by malware to hide execution. |
| False&nbsp;Positives: | LOW                                       |

<details><summary>Additional Information:</summary>

In the Description field of the `UM_APC` detection the following data will be shown in order:
1) ApcNormalRoutine
2) ApcNormalContext Address and description
3) ApcSystemArgument1 Address and description
4) ApcSystemArgument2 Address and description
5) Thread ID (TID)

</details>

---

| `HIGH_ENTROPY`        | High entropy region                       |
| --------------------- | ----------------------------------------- |
| Description:          | HIGH_ENTROPY identifies memory regions with high entropy, commonly used by encrypted malware. |
| False&nbsp;Positives: | MEDIUM : HIGH_ENTROPY memory regions are indicative of encryption regardless if it's used in malware or not. Obfuscated binaries and DRM may trigger false positives. |



### For Developers
The _findevil_ sub-directories are implemented as a built-in native C-code plugin. The plugin source is located in the file _modules/m_fc_findevil.c_ in the _vmm_ project. Scanning for issues are implemented in plugins _m_evil*_.
