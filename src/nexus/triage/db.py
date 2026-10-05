"""Database interfaces for offline triage — known-good baselines and risk context.

known_good.db: File/service/task/autorun baselines from VanillaWindowsReference
context.db: LOLBins, vulnerable drivers, process rules, named pipes, suspicious patterns
"""

import contextlib
import json
import logging
import sqlite3
from functools import lru_cache
from pathlib import Path
from typing import Any

from .analysis import (
    get_hash_column,
    normalize_path,
)

logger = logging.getLogger(__name__)


# =============================================================================
# KnownGoodDB
# =============================================================================

KNOWN_GOOD_SCHEMA = """
CREATE TABLE IF NOT EXISTS baseline_os (
    id INTEGER PRIMARY KEY,
    short_name TEXT UNIQUE NOT NULL,
    os_family TEXT NOT NULL,
    os_edition TEXT,
    os_release TEXT,
    build_number TEXT,
    architecture TEXT DEFAULT 'x64',
    source_csv TEXT,
    imported_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS baseline_files (
    id INTEGER PRIMARY KEY,
    path_normalized TEXT UNIQUE,
    directory_normalized TEXT NOT NULL,
    filename_lower TEXT NOT NULL,
    os_versions TEXT NOT NULL,
    first_seen_source TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_files_path ON baseline_files(path_normalized);
CREATE INDEX IF NOT EXISTS idx_files_filename ON baseline_files(filename_lower);
CREATE TABLE IF NOT EXISTS baseline_hashes (
    id INTEGER PRIMARY KEY,
    hash_value TEXT NOT NULL,
    hash_type TEXT NOT NULL,
    file_id INTEGER NOT NULL,
    os_id INTEGER,
    file_size INTEGER,
    FOREIGN KEY (file_id) REFERENCES baseline_files(id) ON DELETE CASCADE,
    FOREIGN KEY (os_id) REFERENCES baseline_os(id) ON DELETE SET NULL,
    UNIQUE(hash_value, hash_type, file_id)
);
CREATE INDEX IF NOT EXISTS idx_hashes_value ON baseline_hashes(hash_value);
CREATE TABLE IF NOT EXISTS baseline_services (
    id INTEGER PRIMARY KEY,
    service_name_lower TEXT UNIQUE NOT NULL,
    display_name TEXT,
    binary_path_pattern TEXT,
    start_type INTEGER,
    service_type INTEGER,
    object_name TEXT,
    description TEXT,
    os_versions TEXT NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_services_name ON baseline_services(service_name_lower);
CREATE TABLE IF NOT EXISTS baseline_tasks (
    id INTEGER PRIMARY KEY,
    task_path_lower TEXT UNIQUE NOT NULL,
    task_name TEXT,
    uri TEXT,
    actions_summary TEXT,
    triggers_summary TEXT,
    author TEXT,
    os_versions TEXT NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_tasks_path ON baseline_tasks(task_path_lower);
CREATE TABLE IF NOT EXISTS baseline_autoruns (
    id INTEGER PRIMARY KEY,
    hive TEXT NOT NULL,
    key_path_lower TEXT NOT NULL,
    value_name TEXT,
    value_data_pattern TEXT,
    autorun_type TEXT,
    os_versions TEXT NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(hive, key_path_lower, value_name)
);
CREATE INDEX IF NOT EXISTS idx_autoruns_key ON baseline_autoruns(key_path_lower);
CREATE TABLE IF NOT EXISTS sources (name TEXT PRIMARY KEY, source_type TEXT NOT NULL, url TEXT, last_sync_time TEXT, last_sync_commit TEXT, record_count INTEGER DEFAULT 0, notes TEXT);
INSERT OR IGNORE INTO sources (name, source_type, url) VALUES ('vanilla_windows_reference', 'git', 'https://github.com/AndrewRathbun/VanillaWindowsReference');
"""


class KnownGoodDB:
    def __init__(self, db_path: str | Path, read_only: bool = True, cache_size: int = 10000):
        self.db_path = Path(db_path)
        self.read_only = read_only
        self.cache_size = cache_size
        self._conn: sqlite3.Connection | None = None
        if cache_size > 0:
            self._lookup_path_cached = lru_cache(maxsize=cache_size)(self._lookup_path_uncached)
            self._lookup_filename_cached = lru_cache(maxsize=cache_size)(self._lookup_filename_uncached)

    def connect(self) -> sqlite3.Connection:
        if self._conn is None:
            uri = f"file:{self.db_path}?mode=ro" if self.read_only else str(self.db_path)
            self._conn = sqlite3.connect(uri, uri=self.read_only)
            self._conn.row_factory = sqlite3.Row
            if not self.read_only:
                self._conn.execute("PRAGMA journal_mode=WAL")
                self._conn.execute("PRAGMA synchronous=NORMAL")
        return self._conn

    def close(self):
        if self._conn:
            self._conn.close()
            self._conn = None

    def init_schema(self):
        self.connect().executescript(KNOWN_GOOD_SCHEMA)
        self._conn.commit()

    def lookup_by_path(self, path: str) -> list[dict]:
        path_normalized = normalize_path(path)
        if self.cache_size > 0:
            cached = self._lookup_path_cached(path_normalized)
            return [dict(r) for r in cached]
        return [dict(r) for r in self._lookup_path_uncached(path_normalized)]

    def _lookup_path_uncached(self, path_normalized: str) -> tuple:
        conn = self.connect()
        cursor = conn.execute(
            "SELECT bf.*, bh.hash_value, bh.hash_type FROM baseline_files bf "
            "LEFT JOIN baseline_hashes bh ON bf.id = bh.file_id WHERE bf.path_normalized = ?",
            (path_normalized,))
        seen = set()
        results = []
        for row in cursor.fetchall():
            rid = row["id"]
            if rid not in seen:
                entry = {"found": True, "file_id": rid, "path_normalized": row["path_normalized"],
                         "filename": row["filename_lower"],
                         "os_versions": tuple(json.loads(row["os_versions"]))}
                if row["hash_value"]:
                    entry[row["hash_type"]] = row["hash_value"]
                results.append(entry)
                seen.add(rid)
        return tuple(tuple(sorted(r.items())) for r in results)

    def lookup_by_filename(self, filename: str) -> list[dict]:
        fl = filename.lower()
        if self.cache_size > 0:
            cached = self._lookup_filename_cached(fl)
            return [dict(r) for r in cached]
        return [dict(r) for r in self._lookup_filename_uncached(fl)]

    def _lookup_filename_uncached(self, filename_lower: str) -> tuple:
        conn = self.connect()
        cursor = conn.execute(
            "SELECT id, path_normalized, directory_normalized, os_versions FROM baseline_files WHERE filename_lower = ?",
            (filename_lower,))
        results = []
        for row in cursor.fetchall():
            results.append(tuple(sorted({"file_id": row["id"], "path_normalized": row["path_normalized"],
                                         "directory": row["directory_normalized"],
                                         "os_versions": tuple(json.loads(row["os_versions"]))}.items())))
        return tuple(results)

    def filename_exists(self, filename: str) -> bool:
        conn = self.connect()
        cursor = conn.execute("SELECT 1 FROM baseline_files WHERE filename_lower = ? LIMIT 1", (filename.lower(),))
        return cursor.fetchone() is not None

    def path_exists(self, path: str) -> bool:
        conn = self.connect()
        cursor = conn.execute("SELECT 1 FROM baseline_files WHERE path_normalized = ? LIMIT 1", (normalize_path(path),))
        return cursor.fetchone() is not None

    def is_directory_known_for_file(self, filename: str, directory: str) -> bool:
        conn = self.connect()
        cursor = conn.execute(
            "SELECT 1 FROM baseline_files WHERE filename_lower = ? AND directory_normalized = ? LIMIT 1",
            (filename.lower(), directory.lower()))
        return cursor.fetchone() is not None

    def lookup_hash(self, hash_value: str) -> list[dict]:
        conn = self.connect()
        cursor = conn.execute(
            "SELECT h.hash_value, h.hash_type, h.file_size, f.path_normalized, f.filename_lower, f.os_versions "
            "FROM baseline_hashes h JOIN baseline_files f ON h.file_id = f.id WHERE h.hash_value = ?",
            (hash_value.lower(),))
        results = []
        for row in cursor.fetchall():
            results.append({"hash_value": row[0], "hash_type": row[1], "file_size": row[2],
                            "path_normalized": row[3], "filename": row[4],
                            "file_os_versions": json.loads(row[5])})
        return results

    def lookup_service(self, service_name: str) -> list[dict]:
        conn = self.connect()
        cursor = conn.execute("SELECT * FROM baseline_services WHERE service_name_lower = ?",
                              (service_name.lower(),))
        return [dict(row) for row in cursor.fetchall()]

    def lookup_task(self, task_path: str) -> list[dict]:
        conn = self.connect()
        cursor = conn.execute("SELECT * FROM baseline_tasks WHERE task_path_lower = ?",
                              (task_path.lower(),))
        return [dict(row) for row in cursor.fetchall()]

    def lookup_autorun(self, key_path: str, value_name: str | None = None) -> list[dict]:
        conn = self.connect()
        if value_name:
            cursor = conn.execute(
                "SELECT * FROM baseline_autoruns WHERE key_path_lower = ? AND value_name = ?",
                (key_path.lower(), value_name))
        else:
            cursor = conn.execute("SELECT * FROM baseline_autoruns WHERE key_path_lower = ?",
                                  (key_path.lower(),))
        return [dict(row) for row in cursor.fetchall()]

    def get_stats(self) -> dict:
        conn = self.connect()
        stats = {}
        for table, key in [("baseline_os", "os_versions"), ("baseline_files", "files"),
                           ("baseline_hashes", "hashes"), ("baseline_services", "services"),
                           ("baseline_tasks", "tasks"), ("baseline_autoruns", "autoruns")]:
            try:
                cursor = conn.execute(f"SELECT COUNT(*) FROM {table}")
                stats[key] = cursor.fetchone()[0]
            except sqlite3.OperationalError:
                stats[key] = 0
        return stats


# =============================================================================
# RegistryDB
# =============================================================================


class RegistryDB:
    """Interface to optional known_good_registry.db full registry baseline."""

    VALID_HIVES = {"SYSTEM", "SOFTWARE", "NTUSER", "DEFAULT", "SAM", "SECURITY"}

    def __init__(self, db_path: str | Path, read_only: bool = True, cache_size: int = 10000):
        self.db_path = Path(db_path)
        self.read_only = read_only
        self.cache_size = cache_size
        self._conn: sqlite3.Connection | None = None
        if cache_size > 0:
            self._lookup_key_cached = lru_cache(maxsize=cache_size)(self._lookup_key_uncached)
            self._lookup_value_cached = lru_cache(maxsize=cache_size)(self._lookup_value_uncached)

    def connect(self) -> sqlite3.Connection:
        if self._conn is None:
            uri = f"file:{self.db_path}?mode=ro" if self.read_only else str(self.db_path)
            self._conn = sqlite3.connect(uri, uri=self.read_only)
            self._conn.row_factory = sqlite3.Row
        return self._conn

    def close(self):
        if self._conn:
            self._conn.close()
            self._conn = None

    def is_available(self) -> bool:
        if not self.db_path.exists():
            return False
        try:
            cursor = self.connect().execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='baseline_registry'"
            )
            return cursor.fetchone() is not None
        except sqlite3.Error:
            return False

    @staticmethod
    def normalize_key_path(key_path: str) -> str:
        return key_path.replace("/", "\\").lower().strip("\\") if key_path else ""

    @staticmethod
    def extract_hive(key_path: str) -> str | None:
        normalized = key_path.upper().replace("/", "\\").strip("\\")
        if not normalized:
            return None
        parts = normalized.split("\\")
        first = parts[0]
        if first in ("HKEY_CURRENT_USER", "HKCU"):
            return "NTUSER"
        if first in ("HKEY_LOCAL_MACHINE", "HKLM") and len(parts) > 1:
            return parts[1] if parts[1] in RegistryDB.VALID_HIVES else None
        if first in RegistryDB.VALID_HIVES:
            return first
        return None

    def lookup_key(self, key_path: str, hive: str | None = None,
                   os_version: str | None = None) -> list[dict[str, Any]]:
        key_normalized = self.normalize_key_path(key_path)
        if not key_normalized:
            return []
        hive = hive or self.extract_hive(key_path)
        if self.cache_size > 0:
            return list(self._lookup_key_cached(key_normalized, hive, os_version))
        return list(self._lookup_key_uncached(key_normalized, hive, os_version))

    def _lookup_key_uncached(self, key_normalized: str, hive: str | None,
                             os_version: str | None) -> tuple:
        conn = self.connect()
        if hive:
            cursor = conn.execute(
                "SELECT hive, key_path_lower, value_name, value_type, value_data, os_versions "
                "FROM baseline_registry WHERE key_path_lower = ? AND hive = ? "
                "ORDER BY value_name LIMIT 1000",
                (key_normalized, hive.upper()),
            )
        else:
            cursor = conn.execute(
                "SELECT hive, key_path_lower, value_name, value_type, value_data, os_versions "
                "FROM baseline_registry WHERE key_path_lower = ? ORDER BY hive, value_name LIMIT 1000",
                (key_normalized,),
            )
        return tuple(self._row_to_match(row, os_version) for row in cursor if self._row_to_match(row, os_version))

    def lookup_value(self, key_path: str, value_name: str, hive: str | None = None,
                     os_version: str | None = None) -> list[dict[str, Any]]:
        key_normalized = self.normalize_key_path(key_path)
        if not key_normalized:
            return []
        hive = hive or self.extract_hive(key_path)
        if self.cache_size > 0:
            return list(self._lookup_value_cached(key_normalized, value_name, hive, os_version))
        return list(self._lookup_value_uncached(key_normalized, value_name, hive, os_version))

    def _lookup_value_uncached(self, key_normalized: str, value_name: str,
                               hive: str | None, os_version: str | None) -> tuple:
        conn = self.connect()
        if hive:
            cursor = conn.execute(
                "SELECT hive, key_path_lower, value_name, value_type, value_data, os_versions "
                "FROM baseline_registry WHERE key_path_lower = ? AND value_name = ? AND hive = ? LIMIT 1000",
                (key_normalized, value_name, hive.upper()),
            )
        else:
            cursor = conn.execute(
                "SELECT hive, key_path_lower, value_name, value_type, value_data, os_versions "
                "FROM baseline_registry WHERE key_path_lower = ? AND value_name = ? ORDER BY hive LIMIT 1000",
                (key_normalized, value_name),
            )
        return tuple(self._row_to_match(row, os_version) for row in cursor if self._row_to_match(row, os_version))

    @staticmethod
    def _row_to_match(row: sqlite3.Row, os_version: str | None) -> dict | None:
        os_versions = json.loads(row["os_versions"]) if row["os_versions"] else []
        if os_version and os_version not in os_versions:
            return None
        return {
            "hive": row["hive"],
            "key_path": row["key_path_lower"],
            "value_name": row["value_name"],
            "value_type": row["value_type"],
            "value_data": row["value_data"],
            "os_versions": os_versions,
        }

    def get_stats(self) -> dict[str, Any]:
        if not self.is_available():
            return {"available": False}
        conn = self.connect()
        stats = {"available": True}
        stats["registry_entries"] = conn.execute("SELECT COUNT(*) FROM baseline_registry").fetchone()[0]
        try:
            rows = conn.execute("SELECT hive, COUNT(*) FROM baseline_registry GROUP BY hive ORDER BY hive")
            stats["by_hive"] = {row[0]: row[1] for row in rows}
        except sqlite3.Error:
            stats["by_hive"] = {}
        return stats


# =============================================================================
# ContextDB
# =============================================================================

CONTEXT_SCHEMA = """
CREATE TABLE IF NOT EXISTS sources (name TEXT PRIMARY KEY, source_type TEXT NOT NULL, url TEXT, last_sync_time TEXT, last_sync_commit TEXT, record_count INTEGER DEFAULT 0, notes TEXT);
CREATE TABLE IF NOT EXISTS lolbins (id INTEGER PRIMARY KEY, filename_lower TEXT NOT NULL UNIQUE, name TEXT, description TEXT, functions TEXT, expected_paths TEXT, mitre_techniques TEXT, detection TEXT, source_url TEXT);
CREATE INDEX IF NOT EXISTS idx_lol_filename ON lolbins(filename_lower);
CREATE TABLE IF NOT EXISTS hijackable_dlls (id INTEGER PRIMARY KEY, dll_name_lower TEXT NOT NULL, hijack_type TEXT, vulnerable_exe TEXT, vulnerable_exe_path TEXT, expected_paths TEXT, vendor TEXT, UNIQUE(dll_name_lower, vulnerable_exe));
CREATE INDEX IF NOT EXISTS idx_hjk_dll ON hijackable_dlls(dll_name_lower);
CREATE TABLE IF NOT EXISTS vulnerable_drivers (id INTEGER PRIMARY KEY, filename_lower TEXT, sha256 TEXT, sha1 TEXT, md5 TEXT, authentihash_sha256 TEXT, authentihash_sha1 TEXT, authentihash_md5 TEXT, vendor TEXT, product TEXT, cve TEXT, vulnerability_type TEXT, description TEXT);
CREATE INDEX IF NOT EXISTS idx_vd_sha256 ON vulnerable_drivers(sha256) WHERE sha256 IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_vd_sha1 ON vulnerable_drivers(sha1) WHERE sha1 IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_vd_md5 ON vulnerable_drivers(md5) WHERE md5 IS NOT NULL;
CREATE TABLE IF NOT EXISTS expected_processes (id INTEGER PRIMARY KEY, process_name_lower TEXT NOT NULL UNIQUE, valid_parents TEXT, suspicious_parents TEXT, never_spawns_children INTEGER DEFAULT 0, parent_exits INTEGER DEFAULT 0, valid_paths TEXT, user_type TEXT, valid_users TEXT, min_instances INTEGER DEFAULT 1, max_instances INTEGER, per_session INTEGER DEFAULT 0, required_args TEXT, source TEXT);
CREATE INDEX IF NOT EXISTS idx_ep_name ON expected_processes(process_name_lower);
CREATE TABLE IF NOT EXISTS windows_named_pipes (id INTEGER PRIMARY KEY, pipe_name TEXT NOT NULL UNIQUE, pipe_pattern TEXT, protocol TEXT, service_name TEXT, associated_process TEXT, microsoft_doc_url TEXT, description TEXT);
CREATE INDEX IF NOT EXISTS idx_np_name ON windows_named_pipes(pipe_name);
CREATE TABLE IF NOT EXISTS suspicious_filenames (id INTEGER PRIMARY KEY, filename_pattern TEXT NOT NULL UNIQUE, is_regex INTEGER DEFAULT 0, tool_name TEXT, category TEXT, mitre_techniques TEXT, risk_level TEXT DEFAULT 'high', notes TEXT);
CREATE TABLE IF NOT EXISTS suspicious_pipe_patterns (id INTEGER PRIMARY KEY, pipe_pattern TEXT NOT NULL UNIQUE, is_regex INTEGER DEFAULT 0, pipe_example TEXT, tool_name TEXT, malware_family TEXT, mitre_technique TEXT, description TEXT);
CREATE TABLE IF NOT EXISTS protected_process_names (id INTEGER PRIMARY KEY, process_name_lower TEXT NOT NULL UNIQUE, canonical_form TEXT NOT NULL, description TEXT);
CREATE TABLE IF NOT EXISTS lots_domains (id INTEGER PRIMARY KEY, domain_lower TEXT NOT NULL UNIQUE, category TEXT, description TEXT, mitre_technique TEXT, source_url TEXT);
CREATE INDEX IF NOT EXISTS idx_lots_domain ON lots_domains(domain_lower);
CREATE TABLE IF NOT EXISTS loobins (id INTEGER PRIMARY KEY, binary_name_lower TEXT NOT NULL UNIQUE, description TEXT, paths TEXT, functions TEXT, mitre_techniques TEXT, detection TEXT, source_url TEXT);
CREATE INDEX IF NOT EXISTS idx_loobins_name ON loobins(binary_name_lower);
INSERT OR IGNORE INTO sources (name, source_type, url) VALUES ('lolbas', 'git', 'https://github.com/LOLBAS-Project/LOLBAS');
INSERT OR IGNORE INTO sources (name, source_type, url) VALUES ('hijacklibs', 'git', 'https://github.com/wietze/HijackLibs');
INSERT OR IGNORE INTO sources (name, source_type, url) VALUES ('loldrivers_vulnerable', 'git', 'https://github.com/magicsword-io/LOLDrivers');
INSERT OR IGNORE INTO sources (name, source_type, url) VALUES ('lots_project', 'web', 'https://lots-project.com');
INSERT OR IGNORE INTO sources (name, source_type, url) VALUES ('loobins', 'web', 'https://loobins.io');
INSERT OR IGNORE INTO sources (name, source_type, url) VALUES ('lolrmm', 'git', 'https://github.com/Livingofftheland/LOLRMM');
INSERT OR IGNORE INTO sources (name, source_type, url) VALUES ('sans_hunt_evil', 'web', 'https://www.sans.org/posters/hunt-evil/');
INSERT OR IGNORE INTO suspicious_filenames (filename_pattern, tool_name, category, risk_level) VALUES
    ('mimikatz.exe', 'mimikatz', 'credential_theft', 'critical'),
    ('mimi.exe', 'mimikatz', 'credential_theft', 'critical'),
    ('beacon.exe', 'cobalt_strike', 'c2', 'critical'),
    ('rubeus.exe', 'rubeus', 'credential_theft', 'critical'),
    ('seatbelt.exe', 'seatbelt', 'recon', 'high'),
    ('sharphound.exe', 'bloodhound', 'recon', 'high'),
    ('procdump.exe', 'sysinternals', 'credential_theft', 'medium'),
    ('psexec.exe', 'sysinternals', 'lateral_movement', 'medium'),
    ('winpeas.exe', 'winpeas', 'privesc', 'high'),
    ('nc.exe', 'netcat', 'backdoor', 'high'),
    ('chisel.exe', 'chisel', 'tunneling', 'high'),
    ('anydesk.exe', 'anydesk', 'lotrmm', 'high'),
    ('teamviewer.exe', 'teamviewer', 'lotrmm', 'high'),
    ('rustdesk.exe', 'rustdesk', 'lotrmm', 'high'),
    ('screenconnect.exe', 'screenconnect', 'lotrmm', 'high'),
    ('connectwise.exe', 'connectwise', 'lotrmm', 'high'),
    ('splashtop.exe', 'splashtop', 'lotrmm', 'high'),
    ('atera.exe', 'atera', 'lotrmm', 'high'),
    ('client32.exe', 'netsupport_manager', 'lotrmm', 'high'),
    ('meshcentral.exe', 'meshcentral', 'lotrmm', 'high'),
    ('action1.exe', 'action1', 'lotrmm', 'high'),
    ('ninjaone.exe', 'ninjaone', 'lotrmm', 'high'),
    ('logmein.exe', 'logmein', 'lotrmm', 'high'),
    ('kaseya.exe', 'kaseya', 'lotrmm', 'high'),
    ('parsec.exe', 'parsec', 'lotrmm', 'high'),
    ('tightvnc.exe', 'tightvnc', 'lotrmm', 'high'),
    ('vncviewer.exe', 'vncviewer', 'lotrmm', 'high'),
    ('winvnc.exe', 'winvnc', 'lotrmm', 'high');
INSERT OR IGNORE INTO vulnerable_drivers (filename_lower, sha256, vendor, product, cve, vulnerability_type, description) VALUES
    ('gdrv.sys', '72f5d9471b40fd0e7da3c516315eeef39cb5867fb1b5e3f4ae6bc8ec5b53eb6e', 'GIGABYTE', 'GIGABYTE G-Service Driver', 'CVE-2018-19320', 'arbitrary_memory_read_write', 'Abused by RobbinHood ransomware for BYOVD kernel memory write'),
    ('mhyprot2.sys', '046e25944111f182c1611a5b81a74e502c77f0a8253139366e604f5e714dd3ff', 'miHoYo', 'Genshin Impact Anti-Cheat', NULL, 'process_termination', 'Anti-cheat driver abused to bypass protections and kill AV/EDR processes'),
    ('rtcore64.sys', '89fe837b0266016e7886a0b59b583416a206bb41209b5527a2eb17112003c27e', 'Micro-Star International', 'MSI Afterburner', 'CVE-2019-16098', 'arbitrary_memory_read_write', 'Direct hardware/MSR/physical memory read/write abused by BlackCat/ALPHV'),
    ('dbutil_2_3.sys', '0296e2ce999e67c76352613a718e11516fe1b0efc3ffdb8918fc999dd76a73a5', 'Dell', 'Dell BIOS Verification Utility', 'CVE-2021-21551', 'arbitrary_kernel_read_write', 'Dell firmware update driver exposing arbitrary read/write IOCTLs'),
    ('procexp.sys', 'e95759efc7dd3f1245041a998e154f8e5d95e0c5fa600a9fa93e2b26b38cbbab', 'Microsoft Sysinternals', 'Process Explorer Driver', NULL, 'protected_process_kill', 'Signed Sysinternals driver abused to terminate protected AV/EDR processes'),
    ('asriom.sys', '171ebaaec854b7c3d707c576ee3b15ad39fb8fc5b161c56b77207604ad4bc231', 'ASRock', 'ASRock I/O Driver', 'CVE-2020-15368', 'arbitrary_memory_read_write', 'Signed hardware monitoring driver abused to execute unsigned code in kernel'),
    ('enoise.sys', 'b44b8296eb4c029b4cf71eb52ae5da07c2a7db6d0a7a0b5b29f0e1f7c5e26b1c', 'E-Noise', 'E-Noise Hardware Access', NULL, 'kernel_memory_access', 'Abused in BYOVD campaigns to disable driver signature enforcement'),
    ('kprocesshacker.sys', 'f8f01b0bca4cf7450fb6b4df3ea44e45c79be2533c37553f19e2bb9e3d93708c', 'Process Hacker', 'Process Hacker Kernel Driver', NULL, 'kernel_process_termination', 'Kernel driver abused by threat actors to manipulate processes and tokens'),
    ('iqvw64e.sys', '29235e2c560cf8fc67c6eb234c9c193021f156d953a81a7b45f1b2f0a174c86a', 'Intel', 'Intel Network Adapter Diagnostic Driver', 'CVE-2015-2291', 'arbitrary_kernel_write', 'Signed Intel diagnostics driver abused by Turla and Slingshot for kernel execution'),
    ('cpuz141.sys', '9c72e25a176882c3c9f285fb2b23a7bbec437c35f6ea5275e538f121d5a73e5a', 'CPUID', 'CPU-Z Driver', NULL, 'control_register_write', 'CPU monitoring driver abused to modify CR0/CR4 and kernel protections'),
    ('speedfan.sys', 'fbe789ebf3044e13ec932fa5a7828e833486127be5188d3e91d8e11a3b3fa309', 'Almico', 'SpeedFan Monitoring Driver', 'CVE-2007-5633', 'arbitrary_memory_read_write', 'Signed hardware sensor driver allowing arbitrary kernel address read/write'),
    ('atsiv.sys', '6ef8f20b411d51a66bebc2a9ab44cbbf8d2f232df6887556a3507851d7637db9', 'Linchpin Labs', 'Atsiv Loader Driver', NULL, 'unsigned_driver_load', 'Signed utility driver historically abused to load unsigned malicious drivers'),
    ('zamguard64.sys', '4328328c70757d59fe575459392e2fb4208a0d2f091c782a6ea8808d4b8f5ee0', 'Zemana', 'Zemana AntiLogger Driver', 'CVE-2021-31728', 'process_termination', 'Abused by ransomware (ALPHV/BlackCat) to terminate security software');
INSERT OR IGNORE INTO hijackable_dlls (dll_name_lower, hijack_type, vulnerable_exe, vulnerable_exe_path, expected_paths, vendor) VALUES
    ('version.dll', 'search_order', '*', '*', '["C:\\\\Windows\\\\System32"]', 'Microsoft'),
    ('cryptbase.dll', 'search_order', '*', '*', '["C:\\\\Windows\\\\System32"]', 'Microsoft'),
    ('uxtheme.dll', 'search_order', '*', '*', '["C:\\\\Windows\\\\System32"]', 'Microsoft'),
    ('dwmapi.dll', 'search_order', '*', '*', '["C:\\\\Windows\\\\System32"]', 'Microsoft'),
    ('duser.dll', 'search_order', '*', '*', '["C:\\\\Windows\\\\System32"]', 'Microsoft'),
    ('shcore.dll', 'search_order', '*', '*', '["C:\\\\Windows\\\\System32"]', 'Microsoft'),
    ('wldp.dll', 'search_order', '*', '*', '["C:\\\\Windows\\\\System32"]', 'Microsoft'),
    ('amsi.dll', 'search_order', '*', '*', '["C:\\\\Windows\\\\System32"]', 'Microsoft'),
    ('dbghelp.dll', 'search_order', '*', '*', '["C:\\\\Windows\\\\System32"]', 'Microsoft');
INSERT OR IGNORE INTO lots_domains (domain_lower, category, description, mitre_technique, source_url) VALUES
    ('discordapp.com', 'c2_exfil', 'Discord CDN / Webhooks used for C2 and data exfiltration', 'T1102.002', 'https://lots-project.com'),
    ('discord.com', 'c2_exfil', 'Discord Webhooks and bot API abused for C2 channels', 'T1102.002', 'https://lots-project.com'),
    ('api.telegram.org', 'c2_exfil', 'Telegram Bot API leveraged for command-and-control and staging', 'T1102.002', 'https://lots-project.com'),
    ('slack.com', 'c2_exfil', 'Slack API and incoming webhooks abused for interactive C2', 'T1102.002', 'https://lots-project.com'),
    ('webhook.site', 'exfil', 'Webhook receiver service commonly abused for data staging and exfiltration', 'T1567.002', 'https://lots-project.com'),
    ('transfer.sh', 'payload_delivery_exfil', 'Command-line file sharing service used for payload download and exfil', 'T1105', 'https://lots-project.com'),
    ('file.io', 'payload_delivery_exfil', 'Ephemeral file sharing service abused for single-use payload retrieval', 'T1105', 'https://lots-project.com'),
    ('pastebin.com', 'payload_staging', 'Public paste service used for payload hosting and dead-drop resolvers', 'T1102.001', 'https://lots-project.com'),
    ('raw.githubusercontent.com', 'payload_delivery', 'GitHub raw content hosting scripts, staged tools, and secondary stages', 'T1105', 'https://lots-project.com'),
    ('gist.githubusercontent.com', 'payload_delivery', 'GitHub Gist raw content abused for payload delivery', 'T1105', 'https://lots-project.com'),
    ('ngrok.io', 'tunneling_c2', 'Reverse proxy tunnel service abused for ingress and C2 access', 'T1572', 'https://lots-project.com'),
    ('ngrok-free.app', 'tunneling_c2', 'Free tier ngrok tunnel domain commonly observed in intrusion staging', 'T1572', 'https://lots-project.com'),
    ('localtunnel.me', 'tunneling_c2', 'Reverse proxy tunnel service exposing internal ports to the internet', 'T1572', 'https://lots-project.com'),
    ('trycloudflare.com', 'tunneling_c2', 'Cloudflare quick tunnel service abused for ephemeral C2 routing', 'T1572', 'https://lots-project.com');
INSERT OR IGNORE INTO loobins (binary_name_lower, description, paths, functions, mitre_techniques, detection, source_url) VALUES
    ('osascript', 'AppleScript and JXA execution utility used to run code and bypass controls', '["/usr/bin/osascript"]', '["execute", "bypass"]', '["T1059.002"]', 'Monitor process execution of osascript with arguments -e or piping script text', 'https://loobins.io/binaries/osascript/'),
    ('dscl', 'Directory Service command line utility for user/group reconnaissance and privilege modification', '["/usr/bin/dscl"]', '["recon", "privesc"]', '["T1087.001"]', 'Look for dscl commands adding users to admin group or reading shadow hashes', 'https://loobins.io/binaries/dscl/'),
    ('launchctl', 'Service management utility abused for persistence via launch daemons and launch agents', '["/bin/launchctl"]', '["execute", "persistence"]', '["T1543.001", "T1543.004"]', 'Alert on launchctl load / bootstrap from non-standard or user-writable locations', 'https://loobins.io/binaries/launchctl/'),
    ('security', 'Keychain command-line utility abused to dump stored passwords and certificates', '["/usr/bin/security"]', '["credentials"]', '["T1555.001"]', 'Monitor security find-generic-password or dump-keychain commands', 'https://loobins.io/binaries/security/'),
    ('csrutil', 'System Integrity Protection management tool used to inspect protection state', '["/usr/bin/csrutil"]', '["defense_evasion"]', '["T1562.001"]', 'Check for csrutil status execution during discovery phases', 'https://loobins.io/binaries/csrutil/'),
    ('plutil', 'Property list utility abused to inspect or modify configuration and persistence plists', '["/usr/bin/plutil"]', '["defense_evasion", "persistence"]', '["T1647"]', 'Alert on plutil modifications to LaunchAgents or LaunchDaemons plists', 'https://loobins.io/binaries/plutil/'),
    ('defaults', 'Read/write macOS preferences database; abused to disable Gatekeeper or security warnings', '["/usr/bin/defaults"]', '["defense_evasion", "recon"]', '["T1562.001"]', 'Watch for defaults write com.apple.LaunchServices LSQuarantine -bool NO', 'https://loobins.io/binaries/defaults/'),
    ('tccutil', 'Manage Transparency, Consent, and Control database to manipulate app permissions', '["/usr/bin/tccutil"]', '["defense_evasion"]', '["T1562.001"]', 'Alert on tccutil reset commands from unusual parent processes', 'https://loobins.io/binaries/tccutil/'),
    ('spctl', 'Gatekeeper security policy control utility abused to assess or disable Gatekeeper', '["/usr/sbin/spctl"]', '["defense_evasion"]', '["T1553.001"]', 'Monitor spctl --master-disable or assessment-disabling commands', 'https://loobins.io/binaries/spctl/'),
    ('xattr', 'Extended attribute management utility abused to strip com.apple.quarantine attribute', '["/usr/bin/xattr"]', '["defense_evasion"]', '["T1553.001"]', 'Alert on xattr -d -r com.apple.quarantine executed on downloaded binaries', 'https://loobins.io/binaries/xattr/'),
    ('scselect', 'Network setup location selector used during network discovery', '["/usr/sbin/scselect"]', '["recon"]', '["T1016"]', 'Unusual invocation of scselect by non-administrative users', 'https://loobins.io/binaries/scselect/'),
    ('profiles', 'Install, remove, or view configuration profiles; abused for MDM enrollment and persistence', '["/usr/bin/profiles"]', '["persistence", "defense_evasion"]', '["T1176"]', 'Monitor profiles install -type configuration with non-standard payload certificates', 'https://loobins.io/binaries/profiles/'),
    ('system_profiler', 'Detailed hardware/software configuration recon utility', '["/usr/sbin/system_profiler"]', '["recon"]', '["T1082"]', 'System profiler execution with extensive data types during initial intrusion stages', 'https://loobins.io/binaries/system_profiler/'),
    ('curl', 'Command line download tool abused to fetch secondary payloads and exfiltrate data', '["/usr/bin/curl"]', '["download", "exfil"]', '["T1105", "T1567"]', 'Inspect curl piping directly to sh/bash or uploading to cloud storage endpoints', 'https://loobins.io/binaries/curl/'),
    ('python3', 'Script interpreter used for custom backdoors, reverse shells, and post-exploitation', '["/usr/bin/python3"]', '["execute", "c2"]', '["T1059.006"]', 'Inspect python3 interactive reverse shell sockets or memory-injection scripts', 'https://loobins.io/binaries/python3/'),
    ('ruby', 'Script interpreter capable of socket creation, command execution, and payload delivery', '["/usr/bin/ruby"]', '["execute"]', '["T1059"]', 'Monitor ruby execution with -e flags containing socket connections or system calls', 'https://loobins.io/binaries/ruby/');
INSERT OR IGNORE INTO expected_processes (process_name_lower, valid_parents, suspicious_parents, never_spawns_children, parent_exits, valid_paths, user_type, valid_users, min_instances, max_instances, per_session, required_args, source) VALUES
    ('smss.exe', '["System"]', '[]', 0, 0, '["C:\\\\Windows\\\\System32\\\\smss.exe"]', 'system', '["NT AUTHORITY\\\\SYSTEM"]', 1, 1, 0, NULL, 'SANS Hunt Evil'),
    ('csrss.exe', '["smss.exe"]', '[]', 0, 0, '["C:\\\\Windows\\\\System32\\\\csrss.exe"]', 'system', '["NT AUTHORITY\\\\SYSTEM"]', 1, NULL, 1, NULL, 'SANS Hunt Evil'),
    ('wininit.exe', '["smss.exe"]', '[]', 0, 0, '["C:\\\\Windows\\\\System32\\\\wininit.exe"]', 'system', '["NT AUTHORITY\\\\SYSTEM"]', 1, 1, 0, NULL, 'SANS Hunt Evil'),
    ('services.exe', '["wininit.exe"]', '[]', 0, 0, '["C:\\\\Windows\\\\System32\\\\services.exe"]', 'system', '["NT AUTHORITY\\\\SYSTEM"]', 1, 1, 0, NULL, 'SANS Hunt Evil'),
    ('lsass.exe', '["wininit.exe"]', '[]', 1, 0, '["C:\\\\Windows\\\\System32\\\\lsass.exe"]', 'system', '["NT AUTHORITY\\\\SYSTEM"]', 1, 1, 0, NULL, 'SANS Hunt Evil'),
    ('winlogon.exe', '["smss.exe"]', '[]', 0, 0, '["C:\\\\Windows\\\\System32\\\\winlogon.exe"]', 'system', '["NT AUTHORITY\\\\SYSTEM"]', 1, NULL, 1, NULL, 'SANS Hunt Evil'),
    ('explorer.exe', '["userinit.exe"]', '[]', 0, 0, '["C:\\\\Windows\\\\explorer.exe"]', 'user', '[]', 1, NULL, 1, NULL, 'SANS Hunt Evil'),
    ('svchost.exe', '["services.exe"]', '[]', 0, 0, '["C:\\\\Windows\\\\System32\\\\svchost.exe"]', 'system_service', '["NT AUTHORITY\\\\SYSTEM", "NT AUTHORITY\\\\LOCAL SERVICE", "NT AUTHORITY\\\\NETWORK SERVICE"]', 1, NULL, 0, NULL, 'SANS Hunt Evil'),
    ('dwm.exe', '["winlogon.exe"]', '[]', 0, 0, '["C:\\\\Windows\\\\System32\\\\dwm.exe"]', 'user_dwm', '["Window Manager\\\\DWM-1", "Window Manager\\\\DWM-2", "Window Manager\\\\DWM-3", "NT AUTHORITY\\\\SYSTEM"]', 1, NULL, 1, NULL, 'SANS Hunt Evil'),
    ('spoolsv.exe', '["services.exe"]', '[]', 0, 0, '["C:\\\\Windows\\\\System32\\\\spoolsv.exe"]', 'system', '["NT AUTHORITY\\\\SYSTEM"]', 1, 1, 0, NULL, 'SANS Hunt Evil'),
    ('taskhostw.exe', '["svchost.exe", "services.exe"]', '[]', 0, 0, '["C:\\\\Windows\\\\System32\\\\taskhostw.exe"]', 'user_or_system', '[]', 1, NULL, 0, NULL, 'SANS Hunt Evil');
INSERT OR IGNORE INTO suspicious_pipe_patterns (pipe_pattern, is_regex, tool_name, description) VALUES
    ('msagent_*', 1, 'cobalt_strike', 'Default Cobalt Strike pipe'),
    ('MSSE-*', 1, 'cobalt_strike', 'Cobalt Strike SMB beacon'),
    ('postex_*', 1, 'cobalt_strike', 'Cobalt Strike post-exploitation'),
    ('meterpreter', 0, 'metasploit', 'Metasploit named pipe'),
    ('psexecsvc', 0, 'psexec', 'PsExec service pipe');
INSERT OR IGNORE INTO protected_process_names (process_name_lower, canonical_form, description) VALUES
    ('svchost.exe', 'svchost.exe', 'Service Host'), ('csrss.exe', 'csrss.exe', 'Client Server Runtime'),
    ('lsass.exe', 'lsass.exe', 'Local Security Authority'), ('services.exe', 'services.exe', 'Service Control Manager'),
    ('smss.exe', 'smss.exe', 'Session Manager'), ('wininit.exe', 'wininit.exe', 'Windows Initialization'),
    ('winlogon.exe', 'winlogon.exe', 'Windows Logon'), ('explorer.exe', 'explorer.exe', 'Windows Explorer'),
    ('dwm.exe', 'dwm.exe', 'Desktop Window Manager'), ('conhost.exe', 'conhost.exe', 'Console Window Host'),
    ('dllhost.exe', 'dllhost.exe', 'COM Surrogate'), ('spoolsv.exe', 'spoolsv.exe', 'Print Spooler'),
    ('powershell.exe', 'powershell.exe', 'Windows PowerShell'), ('cmd.exe', 'cmd.exe', 'Command Prompt');
INSERT OR IGNORE INTO windows_named_pipes (pipe_name, protocol, service_name, description) VALUES
    ('lsass', 'LSASS', 'Local Security Authority', 'LSA main pipe'),
    ('lsarpc', 'RPC', 'LSA Remote Protocol', 'MS-LSAD'),
    ('samr', 'RPC', 'SAM Remote Protocol', 'MS-SAMR'),
    ('netlogon', 'RPC', 'Netlogon Remote Protocol', 'MS-NRPC'),
    ('srvsvc', 'RPC', 'Server Service', 'MS-SRVS'),
    ('svcctl', 'RPC', 'Service Control Manager', 'MS-SCMR'),
    ('eventlog', 'RPC', 'EventLog Remoting Protocol', 'MS-EVEN'),
    ('spoolss', 'RPC', 'Print Spooler', 'MS-RPRN'),
    ('epmapper', 'RPC', 'Endpoint Mapper', 'MS-RPCE'),
    ('ntsvcs', 'RPC', 'Plug and Play', 'MS-PNP');
"""


class ContextDB:
    def __init__(self, db_path: str | Path, read_only: bool = True, cache_size: int = 10000):
        self.db_path = Path(db_path)
        self.read_only = read_only
        self.cache_size = cache_size
        self._conn: sqlite3.Connection | None = None
        if cache_size > 0:
            self._check_lolbin_cached = lru_cache(maxsize=cache_size)(self._check_lolbin_uncached)
            self._get_expected_process_cached = lru_cache(maxsize=cache_size)(self._get_expected_process_uncached)
            self._get_protected_names_cached = lru_cache(maxsize=1)(self._get_protected_names_uncached)

    def connect(self) -> sqlite3.Connection:
        if self._conn is None:
            uri = f"file:{self.db_path}?mode=ro" if self.read_only else str(self.db_path)
            self._conn = sqlite3.connect(uri, uri=self.read_only)
            self._conn.row_factory = sqlite3.Row
        return self._conn

    def close(self):
        if self._conn:
            self._conn.close()
            self._conn = None

    def init_schema(self):
        self.connect().executescript(CONTEXT_SCHEMA)
        self._conn.commit()

    def check_lolbin(self, filename: str) -> dict | None:
        fl = filename.lower()
        if self.cache_size > 0:
            cached = self._check_lolbin_cached(fl)
            return dict(cached) if cached else None
        result = self._check_lolbin_uncached(fl)
        return dict(result) if result else None

    def _check_lolbin_uncached(self, filename_lower: str) -> tuple | None:
        conn = self.connect()
        cursor = conn.execute("SELECT * FROM lolbins WHERE filename_lower = ?", (filename_lower,))
        row = cursor.fetchone()
        if row:
            result = dict(row)
            for field in ("functions", "expected_paths", "mitre_techniques"):
                if result.get(field):
                    try:
                        parsed = json.loads(result[field])
                        result[field] = tuple(parsed) if isinstance(parsed, list) else parsed
                    except json.JSONDecodeError:
                        pass
            return tuple(sorted(result.items()))
        return None

    def check_vulnerable_driver(self, hash_value: str, algorithm: str) -> dict | None:
        column = get_hash_column(algorithm)
        conn = self.connect()
        cursor = conn.execute(f"SELECT * FROM vulnerable_drivers WHERE {column} = ?", (hash_value.lower(),))
        row = cursor.fetchone()
        if row:
            result = dict(row)
            result["match_type"] = "file_hash"
            return result
        auth_col = f"authentihash_{column}"
        cursor = conn.execute(f"SELECT * FROM vulnerable_drivers WHERE {auth_col} = ?", (hash_value.lower(),))
        row = cursor.fetchone()
        if row:
            result = dict(row)
            result["match_type"] = "authentihash"
            return result
        return None

    def get_expected_process(self, process_name: str) -> dict | None:
        pl = process_name.lower()
        if self.cache_size > 0:
            cached = self._get_expected_process_cached(pl)
        else:
            cached = self._get_expected_process_uncached(pl)
        if cached:
            result = dict(cached)
            for field in ("valid_parents", "suspicious_parents", "valid_paths", "valid_users"):
                if field in result and isinstance(result[field], tuple):
                    result[field] = list(result[field])
            return result
        return None

    def _get_expected_process_uncached(self, process_name_lower: str) -> tuple | None:
        conn = self.connect()
        cursor = conn.execute("SELECT * FROM expected_processes WHERE process_name_lower = ?",
                              (process_name_lower,))
        row = cursor.fetchone()
        if row:
            result = dict(row)
            for field in ("valid_parents", "suspicious_parents", "valid_paths", "valid_users", "required_args"):
                if result.get(field):
                    try:
                        parsed = json.loads(result[field])
                        result[field] = tuple(parsed) if isinstance(parsed, list) else parsed
                    except json.JSONDecodeError:
                        pass
            return tuple(sorted(result.items()))
        return None

    def check_suspicious_filename(self, filename: str) -> dict | None:
        conn = self.connect()
        fl = filename.lower()
        cursor = conn.execute("SELECT * FROM suspicious_filenames WHERE is_regex=0 AND filename_pattern=?", (fl,))
        row = cursor.fetchone()
        if row:
            return dict(row)
        cursor = conn.execute("SELECT * FROM suspicious_filenames WHERE is_regex=1")
        for row in cursor.fetchall():
            try:
                if re.fullmatch(row["filename_pattern"], fl, re.IGNORECASE):
                    return dict(row)
            except re.error:
                continue
        return None

    def check_suspicious_pipe(self, pipe_name: str) -> dict | None:
        conn = self.connect()
        pl = pipe_name.lower()
        cursor = conn.execute("SELECT * FROM suspicious_pipe_patterns WHERE is_regex=0 AND pipe_pattern=?", (pl,))
        row = cursor.fetchone()
        if row:
            return dict(row)
        cursor = conn.execute("SELECT * FROM suspicious_pipe_patterns WHERE is_regex=1")
        for row in cursor.fetchall():
            pattern = row["pipe_pattern"]
            parts = pattern.split("*")
            regex = ".*".join(re.escape(p) for p in parts)
            try:
                if re.fullmatch(regex, pl, re.IGNORECASE):
                    return dict(row)
            except re.error:
                continue
        return None

    def check_windows_pipe(self, pipe_name: str) -> dict | None:
        conn = self.connect()
        cursor = conn.execute("SELECT * FROM windows_named_pipes WHERE pipe_name=?", (pipe_name.lower(),))
        row = cursor.fetchone()
        return dict(row) if row else None

    def check_hijackable_dll(self, dll_name: str) -> list[dict]:
        conn = self.connect()
        cursor = conn.execute("SELECT * FROM hijackable_dlls WHERE dll_name_lower=?", (dll_name.lower(),))
        return [dict(row) for row in cursor.fetchall()]

    def check_driver_by_name(self, driver_name: str) -> dict | None:
        conn = self.connect()
        dl = driver_name.lower().strip()
        cursor = conn.execute("SELECT * FROM vulnerable_drivers WHERE filename_lower = ?", (dl,))
        row = cursor.fetchone()
        if not row and not dl.endswith(".sys"):
            cursor = conn.execute("SELECT * FROM vulnerable_drivers WHERE filename_lower = ?", (f"{dl}.sys",))
            row = cursor.fetchone()
        return dict(row) if row else None

    def check_lots_domain(self, domain: str) -> dict | None:
        conn = self.connect()
        dom = domain.lower().strip().rstrip(".")
        cursor = conn.execute("SELECT * FROM lots_domains WHERE domain_lower = ?", (dom,))
        row = cursor.fetchone()
        if row:
            return dict(row)
        cursor = conn.execute("SELECT * FROM lots_domains")
        for r in cursor.fetchall():
            base = r["domain_lower"]
            if dom == base or dom.endswith(f".{base}"):
                return dict(r)
        return None

    def check_loobin(self, binary_name: str) -> dict | None:
        conn = self.connect()
        bl = binary_name.lower().strip()
        cursor = conn.execute("SELECT * FROM loobins WHERE binary_name_lower = ?", (bl,))
        row = cursor.fetchone()
        if row:
            result = dict(row)
            for field in ("paths", "functions", "mitre_techniques"):
                if result.get(field):
                    with contextlib.suppress(json.JSONDecodeError):
                        result[field] = json.loads(result[field])
            return result
        return None

    def check_protected_process(self, process_name: str) -> dict | None:
        conn = self.connect()
        cursor = conn.execute("SELECT * FROM protected_process_names WHERE process_name_lower=?",
                              (process_name.lower(),))
        row = cursor.fetchone()
        return dict(row) if row else None

    def get_protected_process_names(self) -> list[str]:
        if self.cache_size > 0:
            return list(self._get_protected_names_cached())
        return self._get_protected_names_uncached()

    def _get_protected_names_uncached(self) -> tuple:
        conn = self.connect()
        cursor = conn.execute("SELECT process_name_lower FROM protected_process_names")
        return tuple(row[0] for row in cursor.fetchall())

    def get_stats(self) -> dict:
        conn = self.connect()
        stats = {}
        for table, key in [("lolbins", "lolbins"), ("hijackable_dlls", "hijackable_dlls"),
                           ("vulnerable_drivers", "vulnerable_drivers"),
                           ("expected_processes", "expected_processes"),
                           ("suspicious_filenames", "suspicious_filenames"),
                           ("suspicious_pipe_patterns", "suspicious_pipes"),
                           ("windows_named_pipes", "windows_pipes"),
                           ("protected_process_names", "protected_processes"),
                           ("lots_domains", "lots_domains"),
                           ("loobins", "loobins")]:
            try:
                cursor = conn.execute(f"SELECT COUNT(*) FROM {table}")
                stats[key] = cursor.fetchone()[0]
            except sqlite3.OperationalError:
                stats[key] = 0
        return stats


import re
