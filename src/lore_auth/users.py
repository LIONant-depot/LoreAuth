"""users.json access-code store (no passwords / no SQLite)."""

from __future__ import annotations

import hmac
import json
import secrets
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class UserRecord:
    username: str
    secret: str
    enabled: bool
    expires: Optional[str]
    sub: str
    name: str
    preferred_username: str
    repositories: Dict[str, List[str]] = field(default_factory=dict)

    def is_expired(self, now: Optional[datetime] = None) -> bool:
        if not self.expires:
            return False
        now = now or datetime.now(timezone.utc)
        try:
            exp = datetime.fromisoformat(self.expires.replace("Z", "+00:00"))
        except ValueError:
            return True
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        return now >= exp



def _as_audience_list(raw: Any) -> List[str]:
    """Normalize users.json audience to a list of domain roots."""
    if raw is None:
        return []
    if isinstance(raw, str):
        return [a.strip() for a in raw.split(",") if a.strip()]
    if isinstance(raw, list):
        out: List[str] = []
        for item in raw:
            if isinstance(item, str) and item.strip():
                out.append(item.strip())
        return out
    return []


@dataclass
class UsersConfig:
    path: Path
    issuer: str
    audience: List[str]
    env: str
    token_ttl_hours: int
    codes: Dict[str, UserRecord]

    @classmethod
    def load(cls, path: str | Path) -> "UsersConfig":
        p = Path(path)
        raw = json.loads(p.read_text(encoding="utf-8"))
        codes: Dict[str, UserRecord] = {}
        for username, entry in (raw.get("codes") or {}).items():
            codes[username] = UserRecord(
                username=username,
                secret=str(entry.get("secret", "")),
                enabled=bool(entry.get("enabled", True)),
                expires=entry.get("expires"),
                sub=str(entry.get("sub") or ""),
                name=str(entry.get("name") or username),
                preferred_username=str(
                    entry.get("preferred_username") or username
                ),
                repositories={
                    str(k): list(v)
                    for k, v in (entry.get("repositories") or {}).items()
                },
            )
        return cls(
            path=p,
            issuer=str(raw.get("issuer") or ""),
            audience=_as_audience_list(raw.get("audience")),
            env=str(raw.get("env") or "team3"),
            token_ttl_hours=int(raw.get("token_ttl_hours") or 12),
            codes=codes,
        )

    def save(self) -> None:
        payload: Dict[str, Any] = {
            "issuer": self.issuer,
            "audience": self.audience,
            "env": self.env,
            "token_ttl_hours": self.token_ttl_hours,
            "codes": {},
        }
        for username, u in self.codes.items():
            payload["codes"][username] = {
                "secret": u.secret,
                "enabled": u.enabled,
                "expires": u.expires,
                "sub": u.sub,
                "name": u.name,
                "preferred_username": u.preferred_username,
                "repositories": u.repositories,
            }
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(
            json.dumps(payload, indent=2, sort_keys=False) + "\n",
            encoding="utf-8",
        )

    def find_by_secret(self, secret: str) -> Optional[UserRecord]:
        """Scan all secrets with hmac.compare_digest (constant-time per compare)."""
        if secret is None:
            return None
        secret_b = secret.encode("utf-8")
        match: Optional[UserRecord] = None
        for user in self.codes.values():
            candidate = (user.secret or "").encode("utf-8")
            if len(secret_b) != len(candidate):
                # still perform a compare to keep roughly similar work
                hmac.compare_digest(secret_b, secret_b)
                continue
            if hmac.compare_digest(secret_b, candidate):
                match = user
        return match

    def find_by_username_and_secret(
        self, username: str, secret: str
    ) -> Optional[UserRecord]:
        user = self.codes.get(username)
        secret_b = (secret or "").encode("utf-8")
        if user is None:
            hmac.compare_digest(secret_b, secret_b)
            return None
        candidate = (user.secret or "").encode("utf-8")
        if len(secret_b) != len(candidate):
            hmac.compare_digest(secret_b, secret_b)
            return None
        if not hmac.compare_digest(secret_b, candidate):
            return None
        return user

    def authenticate(
        self,
        secret: str,
        username: Optional[str] = None,
    ) -> Optional[UserRecord]:
        if username:
            user = self.find_by_username_and_secret(username, secret)
        else:
            user = self.find_by_secret(secret)
        if user is None:
            return None
        if not user.enabled or user.is_expired():
            return None
        return user

    def reload(self) -> "UsersConfig":
        return UsersConfig.load(self.path)


def generate_secret(nbytes: int = 24) -> str:
    return secrets.token_urlsafe(nbytes)


def new_user_skeleton(
    username: str,
    name: Optional[str] = None,
    repo_id: Optional[str] = None,
    permissions: Optional[List[str]] = None,
) -> UserRecord:
    repos: Dict[str, List[str]] = {}
    if repo_id:
        repos[repo_id] = permissions or ["read", "write"]
    return UserRecord(
        username=username,
        secret=generate_secret(),
        enabled=True,
        expires="2027-06-30T00:00:00Z",
        sub=str(uuid.uuid4()),
        name=name or username,
        preferred_username=username,
        repositories=repos,
    )
