"""Auto-detect Tailscale MagicDNS issuer/audience and default data dir."""

from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional


@dataclass
class DetectedInit:
    out: Path
    issuer: str
    audience: str  # comma-separated domain roots for JWT aud
    env: str
    dns_name: str
    tailnet_suffix: str
    tailscale_ips: List[str]


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


def audience_csv_for_self(
    *,
    dns_name: str,
    tailnet_suffix: str,
    tailscale_ips: Optional[List[str]] = None,
) -> str:
    """Build JWT aud roots lore's verify_jwt_usage_for_remote can match.

    Lore checks the remote hostname against JWT iss + aud. iss is usually
    https://{dns} and does not match a hostname-only remote, so aud must
    include the MagicDNS name and a leading-dot tailnet suffix. Tailscale
    IPs are included as a best-effort extra (prefer MagicDNS remotes).
    """
    dns = dns_name.rstrip(".")
    suffix = tailnet_suffix.lstrip(".")
    parts: List[str] = [dns, f".{suffix}"]
    for ip in tailscale_ips or []:
        ip = str(ip).strip()
        if ip and ip not in parts:
            parts.append(ip)
    return ",".join(parts)


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
    # hostname.tailnet.ts.net -> suffix tailnet.ts.net
    parts = dns.split(".")
    if len(parts) < 3:
        raise RuntimeError(f"Unexpected MagicDNS name: {dns}")
    tailnet_suffix = ".".join(parts[1:])  # e.g. tail1234.ts.net
    issuer = f"https://{dns}"
    ips = [str(ip) for ip in (self.get("TailscaleIPs") or []) if ip]
    audience = audience_csv_for_self(
        dns_name=dns, tailnet_suffix=tailnet_suffix, tailscale_ips=ips
    )
    return DetectedInit(
        out=out or default_out_dir(),
        issuer=issuer,
        audience=audience,
        env=env,
        dns_name=dns,
        tailnet_suffix=tailnet_suffix,
        tailscale_ips=ips,
    )
