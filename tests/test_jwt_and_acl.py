"""Smoke: mint AuthN/AuthZ JWT, verify claims, JWKS kid match."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from lore_auth.jwks import generate_rsa_keypair, jwks_from_private_key_path  # noqa: E402
from lore_auth.jwt_util import TokenMinter  # noqa: E402
from lore_auth.users import UsersConfig, new_user_skeleton  # noqa: E402
import jwt  # noqa: E402


REPO = "01a066401a037f92bf808b2282c34bb3"


class JwtAclTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.td = Path(self.tmp.name)
        self.key = self.td / "signing-private.pem"
        _, self.jwks = generate_rsa_keypair(self.key, self.td / "pub.pem")
        users_path = self.td / "users.json"
        cfg = UsersConfig(
            path=users_path,
            issuer="https://lore-auth.example.ts.net",
            audience=["lore-host.example.ts.net", ".example.ts.net"],
            env="team3",
            token_ttl_hours=12,
            codes={},
        )
        user = new_user_skeleton("tomas", name="Tomas", repo_id=REPO, permissions=["read", "write", "admin"])
        user.secret = "test-secret-value-123456789012"
        cfg.codes["tomas"] = user
        cfg.save()
        self.cfg = UsersConfig.load(users_path)
        self.minter = TokenMinter(str(self.key), self.cfg, kid=self.jwks["keys"][0]["kid"])

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_authn_claims_and_kid(self) -> None:
        user = self.cfg.codes["tomas"]
        token = self.minter.mint_authn(user)
        header = jwt.get_unverified_header(token)
        self.assertEqual(header.get("alg"), "RS256")
        self.assertEqual(header.get("kid"), self.jwks["keys"][0]["kid"])
        claims = jwt.decode(
            token,
            self.minter.public_key,
            algorithms=["RS256"],
            issuer=self.cfg.issuer,
            options={"verify_aud": False},
        )
        for key in (
            "iss",
            "sub",
            "name",
            "exp",
            "aud",
            "iat",
            "preferred_username",
            "env",
            "idp",
            "is_service_account",
        ):
            self.assertIn(key, claims)
        self.assertEqual(claims["idp"], "access-code")
        self.assertIs(claims["is_service_account"], False)
        self.assertEqual(claims["sub"], user.sub)

    def test_authz_resources_intersect(self) -> None:
        user = self.cfg.codes["tomas"]
        token = self.minter.mint_authz(
            user,
            [f"urc-{REPO}", "urc-deadbeefdeadbeefdeadbeefdeadbeef"],
        )
        claims = jwt.decode(
            token,
            self.minter.public_key,
            algorithms=["RS256"],
            issuer=self.cfg.issuer,
            options={"verify_aud": False},
        )
        resources = claims["resources"]
        ids = [r["resource_id"] for r in resources]
        self.assertEqual(ids, [f"urc-{REPO}"])
        self.assertEqual(resources[0]["permission"], [])

    def test_jwks_roundtrip(self) -> None:
        again = jwks_from_private_key_path(self.key)
        self.assertEqual(again["keys"][0]["kid"], self.jwks["keys"][0]["kid"])
        self.assertEqual(again["keys"][0]["kty"], "RSA")

    def test_authenticate_secret(self) -> None:
        user = self.cfg.authenticate("test-secret-value-123456789012")
        self.assertIsNotNone(user)
        self.assertEqual(user.preferred_username, "tomas")
        self.assertIsNone(self.cfg.authenticate("wrong-secret-value-xxxxxxxxxxxx"))


if __name__ == "__main__":
    unittest.main()
