"""Path normalization and analysis utilities for Windows forensics."""

import math
import re
from collections import Counter

_ENV_EXPANSIONS = {
    "%windir%": r"\windows",
    "%systemroot%": r"\windows",
    "%programfiles%": r"\program files",
    "%programfiles(x86)%": r"\program files (x86)",
    "%programdata%": r"\programdata",
    "%allusersprofile%": r"\programdata",
    "%systemdrive%": "",
    "\\systemroot\\": "\\windows\\",
}

SYSTEM_DIRECTORIES = [
    "\\windows\\system32", "\\windows\\syswow64", "\\windows\\winsxs",
    "\\windows", "\\program files", "\\program files (x86)",
]

SUSPICIOUS_DIRECTORIES = [
    "\\temp", "\\tmp", "\\appdata\\local\\temp", "\\appdata\\roaming",
    "\\users\\public", "\\programdata", "\\windows\\temp",
    "\\downloads", "\\desktop", "\\perflogs", "\\intel", "\\recycler", "\\$recycle.bin",
]


def normalize_path(path: str) -> str:
    if not path:
        return path
    path = path.lower()
    for placeholder, replacement in _ENV_EXPANSIONS.items():
        if path.startswith(placeholder):
            path = replacement + path[len(placeholder):]
            break
    if len(path) > 2 and path[1] == ":":
        path = path[2:]
    path = path.replace("/", "\\")
    stripped = path.rstrip("\\")
    return "\\" if not stripped else stripped


def extract_filename(path: str) -> str:
    if not path:
        return ""
    path = path.replace("/", "\\")
    parts = path.split("\\")
    return parts[-1].lower() if parts else ""


def extract_directory(path: str) -> str:
    if not path:
        return ""
    normalized = normalize_path(path)
    if not normalized:
        return ""
    last_sep = normalized.rfind("\\")
    if last_sep < 0:
        return ""
    if last_sep == 0:
        return "\\"
    return normalized[:last_sep]


def is_system_path(path: str) -> bool:
    normalized = normalize_path(path)
    if not normalized:
        return False
    for sys_dir in SYSTEM_DIRECTORIES:
        if normalized == sys_dir or normalized.startswith(sys_dir + "\\"):
            return True
    return False


def check_suspicious_path(path: str) -> list[dict]:
    findings = []
    normalized = normalize_path(path)
    for suspicious in SUSPICIOUS_DIRECTORIES:
        if suspicious in normalized:
            findings.append({
                "type": "suspicious_directory",
                "severity": "low",
                "matched": suspicious.lstrip("\\"),
                "description": "File in commonly-abused directory",
            })
            break
    return findings


def parse_service_binary_path(image_path: str) -> str:
    if not image_path:
        return ""
    path = image_path.strip()
    if path.startswith('"'):
        end_quote = path.find('"', 1)
        path = path[1:end_quote] if end_quote > 0 else path[1:]
    else:
        exe_match = re.search(r'^([^"]*?\.(exe|sys|dll|ocx))', path, re.IGNORECASE)
        if exe_match:
            path = exe_match.group(1)
        else:
            space_idx = path.find(" ")
            if space_idx > 0:
                path = path[:space_idx]
    path_lower = path.lower()
    if path_lower.startswith("system32\\"):
        path = "\\windows\\system32\\" + path[9:]
    return normalize_path(path)


# =============================================================================
# Hash Utilities
# =============================================================================

HASH_LENGTHS = {32: "md5", 40: "sha1", 64: "sha256"}
HEX_PATTERN = re.compile(r"^[a-fA-F0-9]+$")


def detect_hash_algorithm(hash_str: str) -> str | None:
    if not hash_str:
        return None
    h = hash_str.strip().lower()
    for prefix in ("md5:", "sha1:", "sha256:", "sha-1:", "sha-256:"):
        if h.startswith(prefix):
            h = h[len(prefix):]
            break
    return HASH_LENGTHS.get(len(h))


def normalize_hash(hash_str: str) -> str:
    h = hash_str.strip().lower()
    for prefix in ("md5:", "sha1:", "sha256:", "sha-1:", "sha-256:"):
        if h.startswith(prefix):
            h = h[len(prefix):]
            break
    return h


def get_hash_column(algorithm: str) -> str:
    algo = algorithm.lower().replace("-", "")
    if algo in ("md5", "sha1", "sha256"):
        return algo
    raise ValueError(f"Unknown hash algorithm: {algorithm}")


# =============================================================================
# Unicode Evasion Detection
# =============================================================================

BIDI_OVERRIDES = {
    "\u202e": "Right-to-Left Override (RLO)", "\u202d": "Left-to-Right Override (LRO)",
    "\u202c": "Pop Directional Formatting", "\u202b": "Right-to-Left Embedding",
    "\u202a": "Left-to-Right Embedding", "\u2066": "Left-to-Right Isolate",
    "\u2067": "Right-to-Left Isolate", "\u2068": "First Strong Isolate",
    "\u2069": "Pop Directional Isolate",
}

ZERO_WIDTH_CHARS = {
    "\u200b": "Zero Width Space", "\u200c": "Zero Width Non-Joiner",
    "\u200d": "Zero Width Joiner", "\ufeff": "Byte Order Mark / ZWNBSP",
    "\u00ad": "Soft Hyphen", "\u2060": "Word Joiner",
}

HOMOGLYPHS = {
    "\u0430": ("a", "CYRILLIC A"), "\u0435": ("e", "CYRILLIC IE"),
    "\u043e": ("o", "CYRILLIC O"), "\u0440": ("p", "CYRILLIC ER"),
    "\u0441": ("c", "CYRILLIC ES"), "\u0443": ("y", "CYRILLIC U"),
    "\u0445": ("x", "CYRILLIC HA"), "\u0456": ("i", "CYRILLIC I"),
    "\u0458": ("j", "CYRILLIC JE"), "\u04bb": ("h", "CYRILLIC SHHA"),
    "\u0455": ("s", "CYRILLIC DZE"), "\u0501": ("d", "CYRILLIC KOMI DE"),
    "\u0410": ("A", "CYRILLIC CAP A"), "\u0412": ("B", "CYRILLIC CAP VE"),
    "\u0415": ("E", "CYRILLIC CAP IE"), "\u041d": ("H", "CYRILLIC CAP EN"),
    "\u041e": ("O", "CYRILLIC CAP O"), "\u0420": ("P", "CYRILLIC CAP ER"),
    "\u0421": ("C", "CYRILLIC CAP ES"), "\u0422": ("T", "CYRILLIC CAP TE"),
    "\u0425": ("X", "CYRILLIC CAP HA"), "\u041c": ("M", "CYRILLIC CAP EM"),
    "\u041a": ("K", "CYRILLIC CAP KA"),
    "\u03b1": ("a", "GREEK ALPHA"), "\u03b5": ("e", "GREEK EPSILON"),
    "\u03bf": ("o", "GREEK OMICRON"), "\u03c1": ("p", "GREEK RHO"),
    "\u03c5": ("u", "GREEK UPSILON"), "\u03b9": ("i", "GREEK IOTA"),
    "\u03bd": ("v", "GREEK NU"),
    "\u0391": ("A", "GREEK CAP ALPHA"), "\u0392": ("B", "GREEK CAP BETA"),
    "\u0395": ("E", "GREEK CAP EPSILON"), "\u0397": ("H", "GREEK CAP ETA"),
    "\u0399": ("I", "GREEK CAP IOTA"), "\u039a": ("K", "GREEK CAP KAPPA"),
    "\u039c": ("M", "GREEK CAP MU"), "\u039d": ("N", "GREEK CAP NU"),
    "\u039f": ("O", "GREEK CAP OMICRON"), "\u03a1": ("P", "GREEK CAP RHO"),
    "\u03a4": ("T", "GREEK CAP TAU"), "\u03a7": ("X", "GREEK CAP CHI"),
    "\u0396": ("Z", "GREEK CAP ZETA"),
}

LEET_SUBSTITUTIONS = {"0": ("o",), "1": ("i", "l"), "3": ("e",), "4": ("a",),
                      "5": ("s",), "7": ("t",), "8": ("b",), "@": ("a",), "$": ("s",), "!": ("i",)}


def detect_unicode_evasion(text: str) -> list[dict]:
    findings = []
    for i, char in enumerate(text):
        if char in BIDI_OVERRIDES:
            findings.append({"type": "bidi_override", "severity": "critical",
                             "position": i, "character": repr(char),
                             "unicode_name": BIDI_OVERRIDES[char],
                             "description": "Bidirectional text override - possible RLO attack"})
    for i, char in enumerate(text):
        if char in ZERO_WIDTH_CHARS:
            findings.append({"type": "zero_width", "severity": "high", "position": i,
                             "character": repr(char), "unicode_name": ZERO_WIDTH_CHARS[char],
                             "description": "Zero-width character detected"})
    for i, char in enumerate(text):
        if char in HOMOGLYPHS:
            looks_like, _ = HOMOGLYPHS[char]
            findings.append({"type": "homoglyph", "severity": "high", "position": i,
                             "character": char, "looks_like": looks_like,
                             "description": f'Non-Latin char looking like "{looks_like}"'})
    return findings


def levenshtein_distance(s1: str, s2: str) -> int:
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)
    prev = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        curr = [i + 1]
        for j, c2 in enumerate(s2):
            curr.append(min(prev[j + 1] + 1, curr[j] + 1, prev[j] + (c1 != c2)))
        prev = curr
    return prev[-1]


def detect_typosquatting(text: str, protected_names: list[str], max_distance: int = 2) -> list[dict]:
    findings = []
    text_lower = text.lower()
    if text_lower in (p.lower() for p in protected_names):
        return findings
    matches = []
    for protected in protected_names:
        pl = protected.lower()
        if abs(len(text_lower) - len(pl)) > max_distance:
            continue
        dist = levenshtein_distance(text_lower, pl)
        stem_len = min(len(text_lower.split(".")[0]), len(pl.split(".")[0]))
        effective_max = 1 if stem_len <= 4 else max_distance
        if 0 < dist <= effective_max:
            matches.append((dist, abs(len(text_lower) - len(pl)), protected))
    if matches:
        matches.sort()
        best = matches[0][2]
        findings.append({"type": "typosquatting", "severity": "high",
                         "target_process": best, "actual_name": text,
                         "edit_distance": matches[0][0],
                         "description": f"Possible typosquatting of {best}"})
    return findings


def get_leet_variations(text: str) -> list[str]:
    from itertools import product
    variations = []
    for char in text:
        if char in LEET_SUBSTITUTIONS:
            variations.append(LEET_SUBSTITUTIONS[char])
        else:
            variations.append((char,))
    return ["".join(combo) for combo in product(*variations)]


def detect_leet_speak(text: str, protected_names: list[str]) -> list[dict]:
    findings = []
    has_leet = any(c in LEET_SUBSTITUTIONS for c in text)
    if not has_leet:
        return findings
    text_lower = text.lower()
    variations = get_leet_variations(text_lower)
    for protected in protected_names:
        pl = protected.lower()
        for normalized in variations:
            if normalized == pl and text_lower != pl:
                findings.append({"type": "leet_speak", "severity": "high",
                                 "target_process": protected, "actual_name": text,
                                 "normalized_form": normalized,
                                 "description": f"Leet speak impersonation of {protected}"})
                return findings
    return findings


def check_process_name_spoofing(process_name: str, protected_names: list[str]) -> list[dict]:
    findings = []
    findings.extend(detect_unicode_evasion(process_name))
    findings.extend(detect_leet_speak(process_name, protected_names))
    if not findings:
        findings.extend(detect_typosquatting(process_name, protected_names))
    return findings


# =============================================================================
# Filename Analysis
# =============================================================================

EXECUTABLE_EXTENSIONS = {"exe", "dll", "sys", "scr", "com", "bat", "cmd", "ps1",
                         "psm1", "vbs", "vbe", "js", "jse", "wsf", "wsh", "msc",
                         "hta", "cpl", "msi", "msp", "drv", "ocx", "ax", "jar"}

DOUBLE_EXT_PATTERN = re.compile(
    r"\.(doc|docx|pdf|jpg|jpeg|png|gif|txt|xls|xlsx|ppt|pptx|mp3|mp4|avi|mov)"
    r"\.(exe|scr|com|bat|cmd|ps1|vbs|js|hta|pif|msi)$", re.IGNORECASE)


def calculate_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = Counter(s)
    return -sum((c / len(s)) * math.log2(c / len(s)) for c in freq.values())


def analyze_filename(filename: str) -> dict:
    findings = []
    if "." in filename:
        parts = filename.rsplit(".", 1)
        name_part = parts[0]
        extension = parts[1].lower()
    else:
        name_part = filename
        extension = None
    entropy = calculate_entropy(name_part)
    if extension in EXECUTABLE_EXTENSIONS:
        if len(name_part) <= 2:
            findings.append({"type": "short_name", "severity": "medium",
                             "name_length": len(name_part),
                             "description": f'Very short executable name: "{filename}"'})
        if entropy > 4.5 and len(name_part) > 6:
            findings.append({"type": "high_entropy", "severity": "medium",
                             "entropy": round(entropy, 2),
                             "description": f"High entropy ({entropy:.2f}) suggests random name"})
    if DOUBLE_EXT_PATTERN.search(filename):
        findings.append({"type": "double_extension", "severity": "critical",
                         "description": "Double extension - common masquerading technique"})
    if "        " in filename:
        findings.append({"type": "space_padding", "severity": "high",
                         "description": "Excessive spaces may hide true extension"})
    if name_part.endswith("   "):
        findings.append({"type": "trailing_spaces", "severity": "high",
                         "description": "Trailing spaces before extension"})
    if re.search(r"[\x00-\x1F\x7F]", filename):
        findings.append({"type": "control_chars", "severity": "critical",
                         "description": "Control characters in filename"})
    return {"filename": filename, "entropy": round(entropy, 2),
            "findings": findings, "is_suspicious": len(findings) > 0}


# =============================================================================
# Verdict Calculation
# =============================================================================

from dataclasses import dataclass
from enum import Enum

_MASQUERADE_TARGETS = {
    "atbroker.exe", "audiodg.exe", "bcdedit.exe", "bitsadmin.exe", "certreq.exe",
    "certutil.exe", "cmstp.exe", "conhost.exe", "csrss.exe", "dashost.exe",
    "dfrgui.exe", "dllhost.exe", "dwm.exe", "eventvwr.exe", "explorer.exe",
    "fsquirt.exe", "lsaiso.exe", "lsass.exe", "lsm.exe", "msiexec.exe",
    "powershell.exe", "pwsh.exe", "regsvr32.exe", "rundll32.exe", "runtimebroker.exe",
    "schtasks.exe", "services.exe", "sihost.exe", "smartscreen.exe", "smss.exe",
    "spoolsv.exe", "svchost.exe", "taskhost.exe", "taskhostw.exe", "taskmgr.exe",
    "werfault.exe", "werfaultsecure.exe", "wininit.exe", "winlogon.exe", "wlanext.exe",
    "wscript.exe", "wsmprovhost.exe",
    "consent.exe", "cscript.exe", "defrag.exe", "dism.exe", "dllhst3g.exe",
    "finger.exe", "logonui.exe", "ntoskrnl.exe", "powershell_ise.exe", "runonce.exe",
    "winver.exe", "wsl.exe",
    "backgroundtaskhost.exe", "cmdl32.exe", "eventcreate.exe", "extrac32.exe",
    "fontdrvhost.exe", "ipconfig.exe", "iscsicli.exe", "iscsicpl.exe",
    "logman.exe", "msinfo32.exe", "mstsc.exe", "nbtstat.exe", "odbcconf.exe",
    "regini.exe", "searchfilterhost.exe", "searchindexer.exe",
    "searchprotocolhost.exe", "securityhealthservice.exe",
    "securityhealthsystray.exe", "shellappruntime.exe",
    "systemsettingsbroker.exe", "tiworker.exe", "vssadmin.exe", "w32tm.exe",
    "wermgr.exe", "wevtutil.exe", "winrshost.exe", "winrtnetmuahostserver.exe",
    "wlrmdr.exe", "wmiprvse.exe", "wslhost.exe", "wsreset.exe", "wudfhost.exe",
    "wwahost.exe", "cmd.exe", "sethc.exe",
}


class Verdict(Enum):
    SUSPICIOUS = "SUSPICIOUS"
    EXPECTED_LOLBIN = "EXPECTED_LOLBIN"
    EXPECTED = "EXPECTED"
    UNKNOWN = "UNKNOWN"
    def __str__(self):
        return self.value


@dataclass
class VerdictResult:
    verdict: Verdict
    reasons: list[str]
    confidence: str
    def to_dict(self):
        return {"verdict": str(self.verdict), "reasons": self.reasons, "confidence": self.confidence}


def calculate_file_verdict(path_in_baseline, filename_in_baseline, is_sys_path,
                           filename_findings, lolbin_info, is_protected_process=False,
                           directory_known_for_file=False, dir_normalized="", filename=""):
    reasons = []
    critical_findings = [f for f in filename_findings if f.get("severity") == "critical"]
    if critical_findings:
        reasons.append("Critical filename issues detected")
        for f in critical_findings[:2]:
            reasons.append(f.get("description", f.get("type")))
        return VerdictResult(Verdict.SUSPICIOUS, reasons, "high")

    tool_findings = [f for f in filename_findings if f.get("type") == "known_tool"]
    if tool_findings:
        reasons.append(f"Known tool: {tool_findings[0].get('tool_name', 'unknown')}")
        return VerdictResult(Verdict.SUSPICIOUS, reasons, "high")

    if path_in_baseline:
        if lolbin_info:
            reasons.append("Path matches Windows baseline")
            reasons.append(f"LOLBin: can be abused for {', '.join(lolbin_info.get('functions', [])[:2])}")
            return VerdictResult(Verdict.EXPECTED_LOLBIN, reasons, "high")
        reasons.append("Path matches Windows baseline")
        return VerdictResult(Verdict.EXPECTED, reasons, "high")

    if filename_in_baseline and not path_in_baseline:
        if directory_known_for_file:
            if lolbin_info:
                reasons.append("Filename matches baseline in known directory")
                reasons.append(f"LOLBin: can be abused for {', '.join(lolbin_info.get('functions', [])[:2])}")
                return VerdictResult(Verdict.EXPECTED_LOLBIN, reasons, "medium")
            reasons.append("Filename matches baseline in known directory")
            return VerdictResult(Verdict.EXPECTED, reasons, "medium")
        if filename.lower() in _MASQUERADE_TARGETS:
            reasons.append("System binary in unexpected directory (masquerade indicator)")
            if is_protected_process:
                reasons.append("Protected system process -- high masquerading risk")
                return VerdictResult(Verdict.SUSPICIOUS, reasons, "high")
            return VerdictResult(Verdict.SUSPICIOUS, reasons, "medium")
        reasons.append("Filename in baseline but not a masquerade target")
        return VerdictResult(Verdict.UNKNOWN, reasons, "low")

    high_findings = [f for f in filename_findings if f.get("severity") == "high"]
    if high_findings:
        for f in high_findings[:2]:
            reasons.append(f.get("description", f.get("type")))
        return VerdictResult(Verdict.SUSPICIOUS, reasons, "medium")

    reasons.append("Not in baseline (neutral - may be legitimate third-party software)")
    return VerdictResult(Verdict.UNKNOWN, reasons, "low")


def calculate_process_verdict(process_known, parent_valid, path_valid, user_valid, findings):
    reasons = []
    critical_findings = [f for f in findings if f.get("severity") == "critical"]
    if critical_findings:
        for f in critical_findings:
            reasons.append(f.get("description", f.get("type")))
        return VerdictResult(Verdict.SUSPICIOUS, reasons, "high")
    if not process_known:
        high_findings = [f for f in findings if f.get("severity") == "high"]
        if high_findings:
            for f in high_findings[:2]:
                reasons.append(f.get("description", f.get("type")))
            return VerdictResult(Verdict.SUSPICIOUS, reasons, "medium")
        reasons.append("Process not in expectations database (neutral)")
        return VerdictResult(Verdict.UNKNOWN, reasons, "low")
    if not parent_valid:
        reasons.append("Unexpected parent process")
        return VerdictResult(Verdict.SUSPICIOUS, reasons, "high")
    if path_valid is False:
        reasons.append("Unexpected executable path")
        return VerdictResult(Verdict.SUSPICIOUS, reasons, "high")
    if user_valid is False:
        reasons.append("Unexpected user context")
        return VerdictResult(Verdict.SUSPICIOUS, reasons, "medium")
    reasons.append("Process relationship matches expectations")
    return VerdictResult(Verdict.EXPECTED, reasons, "high")


def calculate_service_verdict(service_in_baseline, binary_path_matches, binary_findings):
    reasons = []
    critical_findings = [f for f in binary_findings if f.get("severity") == "critical"]
    if critical_findings:
        for f in critical_findings[:2]:
            reasons.append(f.get("description", f.get("type")))
        return VerdictResult(Verdict.SUSPICIOUS, reasons, "high")
    if service_in_baseline:
        if binary_path_matches is False:
            reasons.append("Service name in baseline but binary differs - may indicate hijack")
            return VerdictResult(Verdict.SUSPICIOUS, reasons, "medium")
        reasons.append("Service matches Windows baseline")
        return VerdictResult(Verdict.EXPECTED, reasons, "high")
    high_findings = [f for f in binary_findings if f.get("severity") == "high"]
    if high_findings:
        for f in high_findings[:2]:
            reasons.append(f.get("description", f.get("type")))
        return VerdictResult(Verdict.SUSPICIOUS, reasons, "medium")
    reasons.append("Service not in baseline (neutral)")
    return VerdictResult(Verdict.UNKNOWN, reasons, "low")


def calculate_hash_verdict(is_vulnerable_driver=False, driver_info=None, is_lolbin=False, lolbin_info=None):
    reasons = []
    if is_vulnerable_driver and driver_info:
        reasons.append(f"Vulnerable driver: {driver_info.get('product', 'unknown')}")
        if driver_info.get("cve"):
            reasons.append(f"CVE: {driver_info['cve']}")
        return VerdictResult(Verdict.SUSPICIOUS, reasons, "high")
    if is_lolbin and lolbin_info:
        reasons.append(f"LOLBin: {lolbin_info.get('name', 'unknown')}")
        return VerdictResult(Verdict.EXPECTED_LOLBIN, reasons, "medium")
    reasons.append("Hash not found in local databases (neutral). For threat intel, query OpenCTI.")
    return VerdictResult(Verdict.UNKNOWN, reasons, "low")
