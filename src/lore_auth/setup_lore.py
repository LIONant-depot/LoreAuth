"""Discover Lore repo id(s) from a remote via `lore repository list`."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import List, Optional, Tuple

_LIST_LINE = re.compile(
    r"^\s*(?P<name>.+?)\s*\((?P<repo_id>[0-9a-fA-F]{32})\)\s*$"
)

DEFAULT_REMOTE = "lore://100.107.34.33:41337"


@dataclass
class LoreRepo:
    name: str
    repo_id: str


@dataclass
class LoreSetup:
    lore_remote: str
    default_repo_id: str
    default_repo_name: str
    repos: List[dict]

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(asdict(self), indent=2) + "\n", encoding="utf-8")

    @classmethod
    def load(cls, path: Path) -> Optional["LoreSetup"]:
        if not path.is_file():
            return None
        raw = json.loads(path.read_text(encoding="utf-8"))
        return cls(
            lore_remote=str(raw.get("lore_remote") or ""),
            default_repo_id=str(raw.get("default_repo_id") or ""),
            default_repo_name=str(raw.get("default_repo_name") or ""),
            repos=list(raw.get("repos") or []),
        )


def setup_path_for_users(users_path: Path) -> Path:
    return users_path.parent / "lore-setup.json"


def find_lore_exe() -> Optional[str]:
    env = os.environ.get("LORE_EXE")
    if env and Path(env).is_file():
        return env
    return shutil.which("lore") or shutil.which("lore.exe")


def list_remote_repos(remote_url: str, *, lore_exe: Optional[str] = None) -> List[LoreRepo]:
    exe = lore_exe or find_lore_exe()
    if not exe:
        raise FileNotFoundError(
            "lore CLI not found on PATH. Install Lore CLI or set LORE_EXE."
        )
    proc = subprocess.run(
        [exe, "--non-interactive", "repository", "list", remote_url],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    out = (proc.stdout or "") + ("\n" + proc.stderr if proc.stderr else "")
    repos: List[LoreRepo] = []
    for line in out.splitlines():
        m = _LIST_LINE.match(line.strip())
        if m:
            repos.append(
                LoreRepo(name=m.group("name").strip(), repo_id=m.group("repo_id").lower())
            )
    if proc.returncode != 0 and not repos:
        raise RuntimeError(
            f"lore repository list failed (exit {proc.returncode}):\n{out.strip() or '(no output)'}"
        )
    if not repos:
        raise RuntimeError(
            f"No repositories found at {remote_url}. Raw output:\n{out.strip() or '(empty)'}"
        )
    return repos


def auto_setup_lore(
    users_path: Path,
    *,
    remote_url: str = DEFAULT_REMOTE,
    quiet: bool = True,
) -> LoreSetup:
    """Zero-prompt setup: list remote, pick sole repo (or first), save lore-setup.json."""
    exe = find_lore_exe()
    if not exe:
        raise FileNotFoundError("lore CLI not found on PATH")
    if not quiet:
        print(f"Using lore CLI: {exe}")
        print(f"Querying {remote_url} …")
    repos = list_remote_repos(remote_url, lore_exe=exe)
    if len(repos) == 1:
        chosen = repos[0]
    else:
        # Prefer known class name if present, else first
        chosen = next((r for r in repos if r.name == "lore-test-project"), repos[0])
        if not quiet:
            print(f"Multiple repos found; using {chosen.name}")
    setup = LoreSetup(
        lore_remote=remote_url,
        default_repo_id=chosen.repo_id,
        default_repo_name=chosen.name,
        repos=[{"name": r.name, "repo_id": r.repo_id} for r in repos],
    )
    path = setup_path_for_users(users_path)
    setup.save(path)
    if not quiet:
        print(f"Saved class repo as: {chosen.name}")
        print(f"(config: {path})")
    return setup
