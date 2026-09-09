"""CLI: python -m lore_auth"""

from __future__ import annotations

import argparse
import logging
import sys


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="lore-auth",
        description="UCS auth server for LoreGUI (access codes + JWKS, Tailscale HTTPS)",
    )
    p.add_argument("--users", required=True, help="Path to users.json")
    p.add_argument("--private-key", required=True, help="RSA private key PEM for RS256")
    p.add_argument("--cert", default=None, help="TLS cert PEM (Tailscale cert)")
    p.add_argument("--key", default=None, help="TLS private key PEM")
    p.add_argument("--grpc-host", default="0.0.0.0")
    p.add_argument("--grpc-port", type=int, default=443)
    p.add_argument("--http-host", default="0.0.0.0")
    p.add_argument("--http-port", type=int, default=8443)
    p.add_argument(
        "--public-base-url",
        required=True,
        help="Public HTTPS base, e.g. https://lore-auth.<tailnet>.ts.net",
    )
    p.add_argument(
        "--dev",
        action="store_true",
        help="HTTP + insecure gRPC (no TLS). For local smoke only.",
    )
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    if not args.dev and (not args.cert or not args.key):
        print(
            "error: --cert and --key required unless --dev",
            file=sys.stderr,
        )
        return 2
    from .server import run_server

    run_server(
        users_path=args.users,
        private_key_path=args.private_key,
        public_base_url=args.public_base_url,
        grpc_host=args.grpc_host,
        grpc_port=args.grpc_port,
        http_host=args.http_host,
        http_port=args.http_port,
        cert_path=args.cert,
        key_path=args.key,
        dev=args.dev,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
