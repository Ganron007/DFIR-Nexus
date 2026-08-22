"""Remote execution for Stage 0 — SSH, WinRM, local. Never put passwords in argv."""

from __future__ import annotations

import base64
import contextlib
import os
import shutil
import subprocess
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from nexus.collect.types import AuthSpec, HostSpec, TransportName


@dataclass
class ExecResult:
    returncode: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.returncode == 0


class Transport(Protocol):
    name: TransportName

    def probe(self, timeout: int = 30) -> ExecResult: ...
    def run(self, remote_command: str, timeout: int = 600) -> ExecResult: ...
    def put_file(self, local: Path, remote: str, timeout: int = 600) -> ExecResult: ...
    def put_tree(self, local: Path, remote: str, timeout: int = 3600) -> ExecResult: ...
    def get_tree(self, remote: str, local: Path, timeout: int = 3600) -> ExecResult: ...
    def remote_temp(self) -> str: ...


def _run_local(argv: list[str], timeout: int) -> ExecResult:
    if not argv:
        return ExecResult(1, "", "empty command")
    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
        )
        return ExecResult(proc.returncode, proc.stdout or "", proc.stderr or "")
    except FileNotFoundError:
        return ExecResult(127, "", f"not found: {argv[0]}")
    except subprocess.TimeoutExpired:
        return ExecResult(124, "", f"timeout after {timeout}s")


def _which(name: str) -> str | None:
    return shutil.which(name)


def password_from_env(auth: AuthSpec) -> str:
    return (os.environ.get(auth.password_env) or os.environ.get("NEXUS_COLLECT_PASSWORD") or "").strip()


def windows_sftp_path(remote: str) -> str:
    """Normalize a Windows path for OpenSSH scp/SFTP (`/C:/Users/...`)."""
    p = (remote or "").strip().replace("\\", "/")
    if len(p) >= 3 and p[0] == "/" and p[1].isalpha() and p[2] == ":":
        drive = p[1].upper()
        rest = p[3:]
        if rest and not rest.startswith("/"):
            rest = "/" + rest
        return f"/{drive}:{rest}"
    if len(p) >= 2 and p[1] == ":" and p[0].isalpha():
        drive = p[0].upper()
        rest = p[2:]
        if rest and not rest.startswith("/"):
            rest = "/" + rest
        return f"/{drive}:{rest}"
    return p


def windows_ssh_encoded_command(command: str) -> str:
    """Windows OpenSSH default shell is cmd.exe — send PowerShell via EncodedCommand."""
    if "-EncodedCommand" in command or "-encodedcommand" in command.lower():
        return command
    blob = base64.b64encode(
        ("$ProgressPreference = 'SilentlyContinue'; " + command).encode("utf-16le")
    ).decode("ascii")
    return (
        "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass "
        f"-EncodedCommand {blob}"
    )


def _flatten_scp_nest(local: Path, remote: str) -> None:
    """scp -r host:foo dest/ creates dest/foo. Collect wants dest/<contents>."""
    name = Path(str(remote).replace("\\", "/").rstrip("/")).name
    if not name or name in {".", ".."}:
        return
    nested = local / name
    try:
        if not nested.is_dir() or nested.resolve() == local.resolve():
            return
    except OSError:
        return
    for child in list(nested.iterdir()):
        dest = local / child.name
        if dest.exists():
            continue
        try:
            child.rename(dest)
        except OSError:
            continue
    try:
        nested.rmdir()
    except OSError:
        return


def _remote_parent(remote: str) -> str:
    p = remote.replace("\\", "/").rstrip("/")
    if "/" not in p:
        return p
    return p.rsplit("/", 1)[0]


class LocalTransport:
    name: TransportName = "local"

    def __init__(self, spec: HostSpec) -> None:
        self.spec = spec

    def remote_temp(self) -> str:
        base = Path(os.environ.get("TEMP") or os.environ.get("TMP") or "/tmp")
        d = base / f"nexus-ir-{uuid.uuid4().hex[:8]}"
        d.mkdir(parents=True, exist_ok=True)
        return str(d)

    def probe(self, timeout: int = 30) -> ExecResult:
        if os.name == "nt":
            return _run_local(["hostname"], timeout)
        return _run_local(["hostname"], timeout)

    def run(self, remote_command: str, timeout: int = 600) -> ExecResult:
        if os.name == "nt":
            return _run_local(
                ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", remote_command],
                timeout,
            )
        return _run_local(["/bin/sh", "-c", remote_command], timeout)

    def put_file(self, local: Path, remote: str, timeout: int = 600) -> ExecResult:
        dest = Path(remote)
        dest.parent.mkdir(parents=True, exist_ok=True)
        try:
            shutil.copy2(local, dest)
            return ExecResult(0, str(dest), "")
        except OSError as exc:
            return ExecResult(1, "", str(exc))

    def put_tree(self, local: Path, remote: str, timeout: int = 3600) -> ExecResult:
        dest = Path(remote)
        try:
            if dest.exists():
                shutil.copytree(local, dest, dirs_exist_ok=True)
            else:
                shutil.copytree(local, dest)
            return ExecResult(0, str(dest), "")
        except OSError as exec_err:
            return ExecResult(1, "", str(exec_err))

    def get_tree(self, remote: str, local: Path, timeout: int = 3600) -> ExecResult:
        src = Path(remote)
        if not src.exists():
            return ExecResult(1, "", f"missing {remote}")
        try:
            local.parent.mkdir(parents=True, exist_ok=True)
            if src.is_file():
                shutil.copy2(src, local)
            else:
                shutil.copytree(src, local, dirs_exist_ok=True)
            return ExecResult(0, str(local), "")
        except OSError as exc:
            return ExecResult(1, "", str(exc))


class SshTransport:
    name: TransportName = "ssh"

    def __init__(self, spec: HostSpec) -> None:
        self.spec = spec
        self._ssh = _which("ssh")
        self._scp = _which("scp")

    def _base_ssh(self) -> list[str]:
        auth = self.spec.auth
        argv = ["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new"]
        if auth.has_key():
            argv.extend(["-i", str(Path(auth.identity))])
        port = auth.port or 22
        if port != 22:
            argv.extend(["-p", str(port)])
        argv.append(self._target())
        return argv

    def _target(self) -> str:
        user = self.spec.auth.user
        host = self.spec.address
        return f"{user}@{host}" if user else host

    def remote_temp(self) -> str:
        if self.spec.os == "windows":
            return "C:/Windows/Temp/nexus-ir-" + uuid.uuid4().hex[:8]
        return "/tmp/nexus-ir-" + uuid.uuid4().hex[:8]

    def _scp_path(self, remote: str) -> str:
        if self.spec.os == "windows":
            return windows_sftp_path(remote)
        return remote.replace("\\", "/")

    def _ensure_remote_dir(self, remote: str) -> ExecResult:
        if self.spec.os == "windows":
            win = remote.replace("/", "\\")
            quoted = win.replace("'", "''")
            return self.run(
                f"New-Item -ItemType Directory -Force -Path '{quoted}' | Out-Null",
                timeout=60,
            )
        return self.run(f"mkdir -p {remote}", timeout=60)

    def probe(self, timeout: int = 30) -> ExecResult:
        if not self._ssh:
            return ExecResult(127, "", "ssh client not found on this workstation")
        if not self.spec.auth.has_key() and not password_from_env(self.spec.auth):
            return ExecResult(
                2,
                "",
                "SSH needs --identity (key) or NEXUS_COLLECT_PASSWORD (paramiko). "
                "Do not pass a password on the command line.",
            )
        if self.spec.auth.has_key():
            cmd = "hostname" if self.spec.os != "windows" else "hostname.exe"
            return self.run(cmd, timeout=timeout)
        return self._paramiko_run("hostname", timeout)

    def run(self, remote_command: str, timeout: int = 600) -> ExecResult:
        command = remote_command
        if self.spec.os == "windows":
            command = windows_ssh_encoded_command(remote_command)
        if not self.spec.auth.has_key():
            return self._paramiko_run(command, timeout)
        if not self._ssh:
            return ExecResult(127, "", "ssh client not found")
        argv = self._base_ssh() + [command]
        return _run_local(argv, timeout)

    def put_file(self, local: Path, remote: str, timeout: int = 600) -> ExecResult:
        if not self.spec.auth.has_key():
            return self._paramiko_put(local, remote, timeout, tree=False)
        if not self._scp:
            return ExecResult(127, "", "scp not found")
        self._ensure_remote_dir(_remote_parent(remote))
        argv = self._scp_argv() + [str(local), f"{self._target()}:{self._scp_path(remote)}"]
        return _run_local(argv, timeout)

    def put_tree(self, local: Path, remote: str, timeout: int = 3600) -> ExecResult:
        if not local.exists():
            return ExecResult(1, "", f"missing local tree {local}")
        if local.is_file():
            return self.put_file(local, remote, timeout)
        if not self.spec.auth.has_key():
            return self._paramiko_put(local, remote, timeout, tree=True)
        if not self._scp:
            return ExecResult(127, "", "scp not found")
        self._ensure_remote_dir(remote)
        last = ExecResult(0, remote, "")
        for child in sorted(local.iterdir(), key=lambda p: p.name.lower()):
            dest = remote.rstrip("/\\") + "/" + child.name
            if child.is_dir():
                argv = self._scp_argv() + ["-r", str(child), f"{self._target()}:{self._scp_path(dest)}"]
                last = _run_local(argv, timeout)
            else:
                last = self.put_file(child, dest, timeout)
            if not last.ok:
                return last
        return ExecResult(0, remote, "")

    def get_tree(self, remote: str, local: Path, timeout: int = 3600) -> ExecResult:
        if not self.spec.auth.has_key():
            local.mkdir(parents=True, exist_ok=True)
            return self._paramiko_get(remote, local, timeout)
        if not self._scp:
            return ExecResult(127, "", "scp not found")
        spec = f"{self._target()}:{self._scp_path(remote)}"
        remote_name = Path(remote.replace("\\", "/")).name
        looks_file = bool(Path(remote_name).suffix)
        if looks_file and local.suffix:
            local.parent.mkdir(parents=True, exist_ok=True)
            argv = self._scp_argv() + [spec, str(local)]
            return _run_local(argv, timeout)
        local.mkdir(parents=True, exist_ok=True)
        argv = self._scp_argv() + ["-r", spec, str(local)]
        result = _run_local(argv, timeout)
        if result.ok:
            _flatten_scp_nest(local, remote)
        return result

    def _scp_argv(self) -> list[str]:
        auth = self.spec.auth
        argv = ["scp", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new"]
        if auth.has_key():
            argv.extend(["-i", str(Path(auth.identity))])
        port = auth.port or 22
        if port != 22:
            argv.extend(["-P", str(port)])
        return argv

    def _paramiko_run(self, remote_command: str, timeout: int) -> ExecResult:
        try:
            import paramiko
        except ImportError:
            return ExecResult(
                2,
                "",
                "Password SSH needs the optional 'paramiko' package, or use --identity. "
                "pip install paramiko",
            )
        password = password_from_env(self.spec.auth)
        if not password:
            return ExecResult(2, "", f"set {self.spec.auth.password_env} for password SSH")
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(
                self.spec.address,
                port=self.spec.auth.port or 22,
                username=self.spec.auth.user,
                password=password,
                timeout=min(timeout, 60),
                allow_agent=False,
                look_for_keys=False,
            )
            _stdin, stdout, stderr = client.exec_command(remote_command, timeout=timeout)
            out = stdout.read().decode("utf-8", errors="replace")
            err = stderr.read().decode("utf-8", errors="replace")
            code = stdout.channel.recv_exit_status()
            return ExecResult(code, out, err)
        except Exception as exc:  # noqa: BLE001
            return ExecResult(1, "", str(exc))
        finally:
            client.close()

    def _paramiko_put(self, local: Path, remote: str, timeout: int, *, tree: bool) -> ExecResult:
        try:
            import paramiko
        except ImportError:
            return ExecResult(2, "", "paramiko required for password SSH file copy")
        password = password_from_env(self.spec.auth)
        if not password:
            return ExecResult(2, "", f"set {self.spec.auth.password_env}")
        try:
            t = paramiko.Transport((self.spec.address, self.spec.auth.port or 22))
            t.connect(username=self.spec.auth.user, password=password)
            sftp = paramiko.SFTPClient.from_transport(t)
            assert sftp is not None
            if tree:
                _sftp_put_tree(sftp, local, remote)
            else:
                sftp.put(str(local), remote)
            sftp.close()
            t.close()
            return ExecResult(0, remote, "")
        except Exception as exc:  # noqa: BLE001
            return ExecResult(1, "", str(exc))

    def _paramiko_get(self, remote: str, local: Path, timeout: int) -> ExecResult:
        try:
            import paramiko
        except ImportError:
            return ExecResult(2, "", "paramiko required for password SSH file copy")
        password = password_from_env(self.spec.auth)
        if not password:
            return ExecResult(2, "", f"set {self.spec.auth.password_env}")
        try:
            t = paramiko.Transport((self.spec.address, self.spec.auth.port or 22))
            t.connect(username=self.spec.auth.user, password=password)
            sftp = paramiko.SFTPClient.from_transport(t)
            assert sftp is not None
            _sftp_get_tree(sftp, remote, local)
            sftp.close()
            t.close()
            return ExecResult(0, str(local), "")
        except Exception as exc:  # noqa: BLE001
            return ExecResult(1, "", str(exc))


def _sftp_put_tree(sftp, local: Path, remote: str) -> None:
    with contextlib.suppress(OSError):
        sftp.mkdir(remote)
    if local.is_file():
        sftp.put(str(local), remote.rstrip("/") + "/" + local.name)
        return
    for child in local.iterdir():
        dest = remote.rstrip("/") + "/" + child.name
        if child.is_dir():
            _sftp_put_tree(sftp, child, dest)
        else:
            sftp.put(str(child), dest)


def _sftp_get_tree(sftp, remote: str, local: Path) -> None:
    local.mkdir(parents=True, exist_ok=True)
    try:
        attrs = sftp.listdir_attr(remote)
    except OSError:
        local.parent.mkdir(parents=True, exist_ok=True)
        sftp.get(remote, str(local if local.suffix else local / Path(remote).name))
        return
    for entry in attrs:
        name = entry.filename
        rpath = remote.rstrip("/") + "/" + name
        lpath = local / name
        if _sftp_is_dir(sftp, rpath):
            _sftp_get_tree(sftp, rpath, lpath)
        else:
            sftp.get(rpath, str(lpath))


def _sftp_is_dir(sftp, path: str) -> bool:
    try:
        sftp.listdir(path)
        return True
    except OSError:
        return False


class WinRmTransport:
    """Windows remote: pywinrm if present, else PowerShell from a Windows collector."""

    name: TransportName = "winrm"

    def __init__(self, spec: HostSpec) -> None:
        self.spec = spec

    def remote_temp(self) -> str:
        return r"C:\Windows\Temp\nexus-ir-" + uuid.uuid4().hex[:8]

    def probe(self, timeout: int = 30) -> ExecResult:
        return self.run("hostname", timeout=timeout)

    def run(self, remote_command: str, timeout: int = 600) -> ExecResult:
        if _try_import_winrm():
            return self._pywinrm_run(remote_command, timeout)
        if os.name != "nt":
            return ExecResult(
                2,
                "",
                "WinRM from Linux needs pywinrm (pip install pywinrm) or use --transport ssh.",
            )
        return self._ps_invoke(remote_command, timeout)

    def put_file(self, local: Path, remote: str, timeout: int = 600) -> ExecResult:
        return self.put_tree(local, remote, timeout)

    def put_tree(self, local: Path, remote: str, timeout: int = 3600) -> ExecResult:
        if os.name != "nt":
            return ExecResult(
                2,
                "",
                "WinRM file copy from Linux is not wired; use --transport ssh to stage KAPE/Kansa.",
            )
        host = self.spec.address
        # ADMIN$ / C$ requires the same credentials as WinRM.
        unc = _to_unc(host, remote)
        ps = (
            f"$ErrorActionPreference='Stop'; "
            f"{_ps_cred_block(self.spec.auth)} "
            f"New-Item -ItemType Directory -Force -Path '{_ps_escape(unc)}' | Out-Null; "
            f"Copy-Item -Recurse -Force -Path '{_ps_escape(str(local))}' -Destination '{_ps_escape(unc)}'"
        )
        return _run_local(
            ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps],
            timeout,
        )

    def get_tree(self, remote: str, local: Path, timeout: int = 3600) -> ExecResult:
        if os.name != "nt":
            return ExecResult(2, "", "WinRM pull from Linux needs --transport ssh")
        local.mkdir(parents=True, exist_ok=True)
        unc = _to_unc(self.spec.address, remote)
        ps = (
            f"$ErrorActionPreference='Stop'; "
            f"{_ps_cred_block(self.spec.auth)} "
            f"Copy-Item -Recurse -Force -Path '{_ps_escape(unc)}' "
            f"-Destination '{_ps_escape(str(local))}'"
        )
        return _run_local(
            ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps],
            timeout,
        )

    def _pywinrm_run(self, remote_command: str, timeout: int) -> ExecResult:
        import winrm  # type: ignore

        password = password_from_env(self.spec.auth)
        if not password:
            return ExecResult(2, "", f"set {self.spec.auth.password_env} for WinRM")
        user = self.spec.auth.user
        endpoint = f"http://{self.spec.address}:{self.spec.auth.port or 5985}/wsman"
        try:
            s = winrm.Session(endpoint, auth=(user, password), transport="ntlm")
            r = s.run_cmd(remote_command) if not remote_command.lower().startswith("powershell") else s.run_ps(
                remote_command
            )
            out = (r.std_out or b"").decode("utf-8", errors="replace")
            err = (r.std_err or b"").decode("utf-8", errors="replace")
            return ExecResult(int(r.status_code), out, err)
        except Exception as exc:  # noqa: BLE001
            return ExecResult(1, "", str(exc))

    def _ps_invoke(self, remote_command: str, timeout: int) -> ExecResult:
        password = password_from_env(self.spec.auth)
        if not password and not self.spec.auth.has_key():
            # Default credentials (current logon) — still valid on a domain jump box.
            ps = (
                f"Invoke-Command -ComputerName '{_ps_escape(self.spec.address)}' "
                f"-ScriptBlock {{ {remote_command} }}"
            )
        else:
            ps = (
                f"{_ps_cred_block(self.spec.auth)} "
                f"Invoke-Command -ComputerName '{_ps_escape(self.spec.address)}' "
                f"-Credential $cred -ScriptBlock {{ {remote_command} }}"
            )
        return _run_local(
            ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps],
            timeout,
        )


def _try_import_winrm() -> bool:
    try:
        import winrm  # noqa: F401
        return True
    except ImportError:
        return False


def _ps_escape(value: str) -> str:
    return value.replace("'", "''")


def _ps_cred_block(auth: AuthSpec) -> str:
    env = auth.password_env or "NEXUS_COLLECT_PASSWORD"
    user = _ps_escape(auth.user)
    return (
        f"$p = [Environment]::GetEnvironmentVariable('{_ps_escape(env)}'); "
        f"if (-not $p) {{ throw 'password env {env} empty' }}; "
        f"$sec = ConvertTo-SecureString $p -AsPlainText -Force; "
        f"$cred = New-Object System.Management.Automation.PSCredential('{user}', $sec);"
    )


def _to_unc(host: str, windows_path: str) -> str:
    p = windows_path.replace("/", "\\")
    if p.startswith("\\\\"):
        return p
    if len(p) >= 2 and p[1] == ":":
        drive = p[0]
        rest = p[2:].lstrip("\\")
        return f"\\\\{host}\\{drive}$\\{rest}"
    return f"\\\\{host}\\C$\\{p.lstrip('\\')}"


def connect(spec: HostSpec) -> Transport:
    if spec.transport == "local" or spec.address in {"localhost", "127.0.0.1", "::1"}:
        return LocalTransport(spec)
    if spec.transport == "winrm":
        return WinRmTransport(spec)
    return SshTransport(spec)
