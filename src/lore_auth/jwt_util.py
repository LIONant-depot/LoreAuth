"""RS256 JWT mint/verify for AuthN and AuthZ tokens."""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional, Sequence

import jwt

from .jwks import kid_from_public_numbers, load_private_key, public_key_from_private
from .users import UserRecord, UsersConfig


class TokenMinter:
    def __init__(
        self,
        private_key_path: str,
        users: UsersConfig,
        kid: Optional[str] = None,
    ):
        self.private_key_path = private_key_path
        self.private_key = load_private_key(private_key_path)
        self.public_key = public_key_from_private(self.private_key)
        numbers = self.public_key.public_numbers()
        self.kid = kid or kid_from_public_numbers(numbers.n, numbers.e)
        self.users = users

    def _base_claims(self, user: UserRecord, ttl_hours: Optional[int] = None) -> Dict[str, Any]:
        now = int(time.time())
        ttl = int((ttl_hours if ttl_hours is not None else self.users.token_ttl_hours) * 3600)
        return {
            "iss": self.users.issuer,
            "sub": user.sub,
            "name": user.name,
            "preferred_username": user.preferred_username,
            "is_service_account": False,
            "iat": now,
            "exp": now + ttl,
            "aud": list(self.users.audience),
            "env": self.users.env,
            "idp": "access-code",
        }

    def mint_authn(self, user: UserRecord) -> str:
        claims = self._base_claims(user)
        return jwt.encode(
            claims,
            self.private_key,
            algorithm="RS256",
            headers={"kid": self.kid, "alg": "RS256", "typ": "JWT"},
        )

    def mint_authz(
        self,
        user: UserRecord,
        resource_ids: Sequence[str],
    ) -> str:
        """Intersect requested resource_ids with user's ACL; permission arrays empty."""
        allowed_hex = set(user.repositories.keys())
        resources: List[Dict[str, Any]] = []
        for rid in resource_ids:
            rid = rid.strip()
            if not rid:
                continue
            hex_id = rid[4:] if rid.startswith("urc-") else rid
            full = rid if rid.startswith("urc-") else f"urc-{rid}"
            if hex_id in allowed_hex or "*" in allowed_hex or "urc-*" in user.repositories:
                # empty permission array per design (loreserver matches resource_id only)
                resources.append({"resource_id": full, "permission": []})
            elif full in allowed_hex:
                resources.append({"resource_id": full, "permission": []})
        claims = self._base_claims(user)
        claims["resources"] = resources
        return jwt.encode(
            claims,
            self.private_key,
            algorithm="RS256",
            headers={"kid": self.kid, "alg": "RS256", "typ": "JWT"},
        )

    def verify(self, token: str) -> Dict[str, Any]:
        return jwt.decode(
            token,
            self.public_key,
            algorithms=["RS256"],
            audience=self.users.audience[0] if self.users.audience else None,
            issuer=self.users.issuer or None,
            options={
                "require": ["exp", "iat", "iss", "sub", "aud"],
                "verify_aud": bool(self.users.audience),
            },
        )

    def user_from_claims(self, claims: Dict[str, Any]) -> Optional[UserRecord]:
        sub = claims.get("sub")
        for user in self.users.codes.values():
            if user.sub == sub:
                return user
        return None
