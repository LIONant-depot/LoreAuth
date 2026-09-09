"""Auto-detect Tailscale MagicDNS issuer/audience and default data dir."""

from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass
class DetectedInit:
    out: Path
    issuer: str
    audience: str  # comma-separated
    env: str
    dns_name: str
    tailnet_suffix: str


def _run_tailscale_status() -> dict:
    exe = shutil.which("tailscale") or shutil.which("tailscale.exe")
    if not exe:
        raise FileNotFoundError(
            "tailscale CLI not found on PATH. Install Tailscale or pass --issuer/--audience manually."
        )
    proc = subprocess.run(
        [exe, "status", "--json"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"tailscale status --json failed (exit {proc.returncode}): "
            f"{(proc.stderr or proc.stdout or '').strip()}"
        )
    return json.loads(proc.stdout)


def default_out_dir() -> Path:
    preferred = Path("/opt/lore-auth/data")
    if preferred.is_dir() or preferred.parent.is_dir():
        return preferred
    return Path("dev-data")


def detect_init(*, out: Optional[Path] = None, env: str = "team3") -> DetectedInit:
    """Derive issuer/audience from this machine's Tailscale MagicDNS name."""
    status = _run_tailscale_status()
    self = status.get("Self") or {}
    dns = str(self.get("DNSName") or "").rstrip(".")
    if not dns or "." not in dns:
        raise RuntimeError(
            "Could not read MagicDNS name from `tailscale status --json` "
            "(Self.DNSName). Is MagicDNS enabled and is this node online?"
        )
    # hostname.tailnet.ts.net → suffix tailnet.ts.net
    parts = dns.split(".")
    if len(parts) < 3:
        raise RuntimeError(f"Unexpected MagicDNS name: {dns}")
    tailnet_suffix = ".".join(parts[1:])  # e.g. tail1234.ts.net
    issuer = f"https://{dns}"
    # aud must cover the lore remote host domain. Same-VM default: this host + leading-dot tailnet.
    audience = f"{dns},.{tailnet_suffix}"
    return DetectedInit(
        out=out or default_out_dir(),
        issuer=issuer,
        audience=audience,
        env=env,
        dns_name=dns,
        tailnet_suffix=tailnet_suffix,
    )
