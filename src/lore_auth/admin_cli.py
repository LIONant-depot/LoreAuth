"""lore-auth-admin: init / add-user / disable / rotate / set-repo / list."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from types import SimpleNamespace

from .detect import detect_init
from .jwks import generate_rsa_keypair, write_jwks
from .users import UsersConfig, generate_secret, new_user_skeleton


def cmd_init(args: argparse.Namespace) -> int:
    if getattr(args, "auto", False):
        try:
            det = detect_init(
                out=Path(args.out) if getattr(args, "out", None) else None,
                env=getattr(args, "env", None) or "team3",
            )
        except Exception as exc:  # noqa: BLE001
            print(f"auto-detect failed: {exc}", file=sys.stderr)
            return 1
        print("Auto-detected from Tailscale:")
        print(f"  out      = {det.out}")
        print(f"  issuer   = {det.issuer}")
        print(f"  audience = {det.audience}")
        print(f"  env      = {det.env}")
        print(f"  dns      = {det.dns_name}")
        args = SimpleNamespace(
            out=str(det.out),
            issuer=det.issuer,
            audience=det.audience,
            env=det.env,
            ttl_hours=getattr(args, "ttl_hours", 12) or 12,
            force=bool(getattr(args, "force", False)),
        )

    if not getattr(args, "out", None) or not getattr(args, "issuer", None):
        print("init requires --out and --issuer (or use --auto)", file=sys.stderr)
        return 1

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    users_path = out / "users.json"
    key_path = out / "signing-private.pem"
    pub_path = out / "signing-public.pem"
    jwks_path = out / "public-jwks.json"

    if users_path.exists() and not args.force:
        print(f"refusing to overwrite {users_path} (use --force)", file=sys.stderr)
        return 1

    issuer = args.issuer.rstrip("/")
    audience = [a.strip() for a in args.audience.split(",") if a.strip()]
    cfg = UsersConfig(
        path=users_path,
        issuer=issuer,
        audience=audience,
        env=args.env,
        token_ttl_hours=args.ttl_hours,
        codes={},
    )
    cfg.save()
    _, jwks = generate_rsa_keypair(key_path, pub_path)
    write_jwks(jwks, jwks_path)
    print(f"wrote {users_path}")
    print(f"wrote {key_path}")
    print(f"wrote {pub_path}")
    print(f"wrote {jwks_path}")
    print(f"kid={jwks['keys'][0]['kid']}")
    return 0


def cmd_add_user(args: argparse.Namespace) -> int:
    cfg = UsersConfig.load(args.users)
    if args.username in cfg.codes and not args.force:
        print(f"user {args.username} exists (use --force)", file=sys.stderr)
        return 1
    user = new_user_skeleton(
        username=args.username,
        name=args.name or args.username,
        repo_id=args.repo,
        permissions=(args.permissions.split(",") if args.permissions else None),
    )
    if args.secret:
        user.secret = args.secret
    cfg.codes[args.username] = user
    cfg.save()
    print(json.dumps({"username": args.username, "secret": user.secret, "sub": user.sub}, indent=2))
    return 0


def cmd_disable_user(args: argparse.Namespace) -> int:
    cfg = UsersConfig.load(args.users)
    user = cfg.codes.get(args.username)
    if not user:
        print(f"unknown user {args.username}", file=sys.stderr)
        return 1
    user.enabled = False
    cfg.save()
    print(f"disabled {args.username}")
    return 0


def cmd_rotate_secret(args: argparse.Namespace) -> int:
    cfg = UsersConfig.load(args.users)
    user = cfg.codes.get(args.username)
    if not user:
        print(f"unknown user {args.username}", file=sys.stderr)
        return 1
    user.secret = args.secret or generate_secret()
    cfg.save()
    print(json.dumps({"username": args.username, "secret": user.secret}, indent=2))
    return 0


def cmd_set_repo(args: argparse.Namespace) -> int:
    cfg = UsersConfig.load(args.users)
    user = cfg.codes.get(args.username)
    if not user:
        print(f"unknown user {args.username}", file=sys.stderr)
        return 1
    perms = args.permissions.split(",") if args.permissions else ["read", "write"]
    user.repositories[args.repo] = perms
    cfg.save()
    print(json.dumps({"username": args.username, "repositories": user.repositories}, indent=2))
    return 0


def cmd_list(args: argparse.Namespace) -> int:
    cfg = UsersConfig.load(args.users)
    rows = []
    for u in cfg.codes.values():
        rows.append(
            {
                "username": u.username,
                "enabled": u.enabled,
                "expires": u.expires,
                "sub": u.sub,
                "name": u.name,
                "repos": list(u.repositories.keys()),
            }
        )
    print(json.dumps({"issuer": cfg.issuer, "env": cfg.env, "users": rows}, indent=2))
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="lore-auth-admin")
    sub = p.add_subparsers(dest="cmd", required=True)

    init = sub.add_parser(
        "init",
        help="Create users.json skeleton + RSA keypair + JWKS",
    )
    init.add_argument(
        "--auto",
        action="store_true",
        help="Detect issuer/audience/out from Tailscale MagicDNS (recommended on the VM)",
    )
    init.add_argument(
        "--out",
        default=None,
        help="Output directory (default with --auto: /opt/lore-auth/data or ./dev-data)",
    )
    init.add_argument(
        "--issuer",
        default=None,
        help="Issuer URL (not needed with --auto)",
    )
    init.add_argument(
        "--audience",
        default="lore-host.<tailnet>.ts.net,.<tailnet>.ts.net",
        help="Comma-separated aud values (overridden by --auto)",
    )
    init.add_argument("--env", default="team3")
    init.add_argument("--ttl-hours", type=int, default=12)
    init.add_argument("--force", action="store_true")
    init.set_defaults(func=cmd_init)

    add = sub.add_parser("add-user")
    add.add_argument("--users", required=True)
    add.add_argument("--username", required=True)
    add.add_argument("--name", default=None)
    add.add_argument("--repo", default=None, help="32-hex repo id")
    add.add_argument("--permissions", default="read,write")
    add.add_argument("--secret", default=None)
    add.add_argument("--force", action="store_true")
    add.set_defaults(func=cmd_add_user)

    dis = sub.add_parser("disable-user")
    dis.add_argument("--users", required=True)
    dis.add_argument("--username", required=True)
    dis.set_defaults(func=cmd_disable_user)

    rot = sub.add_parser("rotate-secret")
    rot.add_argument("--users", required=True)
    rot.add_argument("--username", required=True)
    rot.add_argument("--secret", default=None)
    rot.set_defaults(func=cmd_rotate_secret)

    sr = sub.add_parser("set-repo")
    sr.add_argument("--users", required=True)
    sr.add_argument("--username", required=True)
    sr.add_argument("--repo", required=True)
    sr.add_argument("--permissions", default="read,write")
    sr.set_defaults(func=cmd_set_repo)

    ls = sub.add_parser("list")
    ls.add_argument("--users", required=True)
    ls.set_defaults(func=cmd_list)

    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
