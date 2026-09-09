"""Background start/stop + PID tracking for lore-auth and loreserver."""

from __future__ import annotations

import os
import signal
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


RUN_DIR = Path("/opt/lore-auth/run")
LOG_DIR = Path("/opt/lore-auth/log")


@dataclass
class ServiceSpec:
    name: str
    pid_file: Path
    log_file: Path

    @classmethod
    def auth(cls) -> "ServiceSpec":
        return cls(
            name="authentication-server",
            pid_file=RUN_DIR / "auth.pid",
            log_file=LOG_DIR / "auth.log",
        )

    @classmethod
    def lore(cls) -> "ServiceSpec":
        return cls(
            name="lore-server",
            pid_file=RUN_DIR / "lore.pid",
            log_file=LOG_DIR / "lore.log",
        )


def _ensure_dirs() -> None:
    try:
        RUN_DIR.mkdir(parents=True, exist_ok=True)
        LOG_DIR.mkdir(parents=True, exist_ok=True)
    except PermissionError as exc:
        raise PermissionError(
            f"Cannot write {RUN_DIR} / {LOG_DIR} ({exc}). "
            "Run Setup authentication server once, or: "
            f"sudo mkdir -p {RUN_DIR} {LOG_DIR} && "
            f"sudo chown -R $USER:$USER {RUN_DIR} {LOG_DIR}"
        ) from exc


def pid_running(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    else:
        return True


def _cmdline(pid: int) -> str:
    try:
        raw = Path(f"/proc/{pid}/cmdline").read_bytes()
    except OSError:
        return ""
    return raw.replace(b"\x00", b" ").decode("utf-8", "replace").strip()


def _iter_pids() -> list[int]:
    proc = Path("/proc")
    if not proc.is_dir():
        return []
    out: list[int] = []
    for entry in proc.iterdir():
        if entry.name.isdigit():
            out.append(int(entry.name))
    return out


def discover_auth_pid() -> Optional[int]:
    """Find a live lore-auth server even if started outside the menu."""
    for pid in _iter_pids():
        cmd = _cmdline(pid)
        if not cmd:
            continue
        if "lore_auth.menu" in cmd:
            continue
        # python -m lore_auth ... (server), not menu
        if "-m lore_auth" in cmd or "lore_auth.__main__" in cmd:
            return pid
        if "python" in cmd and "lore_auth" in cmd and "menu" not in cmd:
            # e.g. .../python -m lore_auth --users ...
            if " -m lore_auth" in f" {cmd}" or cmd.rstrip().endswith("lore_auth"):
                return pid
    return None


def discover_lore_pid() -> Optional[int]:
    """Find a live loreserver even if started outside the menu."""
    for pid in _iter_pids():
        cmd = _cmdline(pid)
        if not cmd:
            continue
        # binary path or bare name
        base = Path(cmd.split(" ", 1)[0]).name
        if base == "loreserver" or "/loreserver " in f"{cmd} " or cmd.startswith("loreserver"):
            return pid
        if "loreserver" in cmd and "--config" in cmd:
            return pid
    return None


def discover_pid(spec: ServiceSpec) -> Optional[int]:
    if spec.name == "authentication-server":
        return discover_auth_pid()
    if spec.name == "lore-server":
        return discover_lore_pid()
    return None


def _adopt_pid(spec: ServiceSpec, pid: int) -> None:
    try:
        _ensure_dirs()
        spec.pid_file.write_text(str(pid) + "\n", encoding="utf-8")
    except OSError:
        pass


def read_pid(spec: ServiceSpec) -> Optional[int]:
    if spec.pid_file.is_file():
        try:
            pid = int(spec.pid_file.read_text(encoding="utf-8").strip())
        except ValueError:
            pid = None
        else:
            if pid_running(pid):
                return pid
            try:
                spec.pid_file.unlink()
            except OSError:
                pass

    # Fall back: process started outside the menu (no PID file)
    found = discover_pid(spec)
    if found is not None and pid_running(found):
        _adopt_pid(spec, found)
        return found
    return None


def is_running(spec: ServiceSpec) -> bool:
    return read_pid(spec) is not None


def start_background(
    spec: ServiceSpec,
    argv: list[str],
    *,
    cwd: Optional[str] = None,
    env: Optional[dict] = None,
) -> int:
    """Start argv in background; return PID."""
    if is_running(spec):
        raise RuntimeError(f"{spec.name} is already running (pid {read_pid(spec)})")
    _ensure_dirs()
    log_f = open(spec.log_file, "a", encoding="utf-8")
    log_f.write(f"\n--- start {' '.join(argv)} ---\n")
    log_f.flush()
    proc = subprocess.Popen(
        argv,
        cwd=cwd,
        env=env or os.environ.copy(),
        stdout=log_f,
        stderr=subprocess.STDOUT,
        start_new_session=True,
        close_fds=True,
    )
    spec.pid_file.write_text(str(proc.pid) + "\n", encoding="utf-8")
    time.sleep(0.4)
    if proc.poll() is not None:
        try:
            spec.pid_file.unlink()
        except OSError:
            pass
        raise RuntimeError(
            f"{spec.name} exited immediately (code {proc.returncode}). See {spec.log_file}"
        )
    return proc.pid


def stop_service(spec: ServiceSpec, *, timeout: float = 8.0) -> None:
    pid = read_pid(spec)
    if pid is None:
        raise RuntimeError(f"{spec.name} is not running")
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    deadline = time.time() + timeout
    while time.time() < deadline:
        if not pid_running(pid):
            break
        time.sleep(0.2)
    if pid_running(pid):
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    try:
        spec.pid_file.unlink()
    except OSError:
        pass
