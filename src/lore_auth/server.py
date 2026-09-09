"""Start gRPC + HTTP servers for lore-auth."""

from __future__ import annotations

import logging
import ssl
import threading
from concurrent import futures
from pathlib import Path
from typing import Optional

import grpc
import uvicorn

from .grpc_servicer import add_to_server, build_servicer_class
from .http_app import create_app
from .jwks import jwks_from_private_key_path
from .jwt_util import TokenMinter
from .sessions import SessionStore
from .users import UsersConfig

log = logging.getLogger("lore_auth.server")


def run_server(
    *,
    users_path: str,
    private_key_path: str,
    public_base_url: str,
    grpc_host: str = "0.0.0.0",
    grpc_port: int = 443,
    http_host: str = "0.0.0.0",
    http_port: int = 8443,
    cert_path: Optional[str] = None,
    key_path: Optional[str] = None,
    dev: bool = False,
) -> None:
    users = UsersConfig.load(users_path)
    if not users.issuer and public_base_url:
        users.issuer = public_base_url.rstrip("/")
    jwks = jwks_from_private_key_path(private_key_path)
    minter = TokenMinter(private_key_path, users, kid=jwks["keys"][0]["kid"])
    sessions = SessionStore()

    def reload_users() -> UsersConfig:
        cfg = UsersConfig.load(users_path)
        if not cfg.issuer and public_base_url:
            cfg.issuer = public_base_url.rstrip("/")
        minter.users = cfg
        return cfg

    Servicer = build_servicer_class()
    servicer = Servicer(
        users=users,
        sessions=sessions,
        minter=minter,
        public_base_url=public_base_url,
    )

    # --- gRPC ---
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=8))
    add_to_server(server, servicer)

    use_tls = not dev and cert_path and key_path
    grpc_addr = f"{grpc_host}:{grpc_port}"
    if use_tls:
        with open(key_path, "rb") as f:
            private_key = f.read()
        with open(cert_path, "rb") as f:
            certificate_chain = f.read()
        creds = grpc.ssl_server_credentials(
            [(private_key, certificate_chain)],
            require_client_auth=False,
        )
        server.add_secure_port(grpc_addr, creds)
        log.info("gRPC TLS listening on %s", grpc_addr)
    else:
        server.add_insecure_port(grpc_addr)
        log.info("gRPC insecure (--dev) listening on %s", grpc_addr)

    server.start()

    # --- HTTP (Starlette + uvicorn) ---
    app = create_app(
        users=users,
        sessions=sessions,
        minter=minter,
        jwks=jwks,
        reload_users=reload_users,
    )

    ssl_kwargs = {}
    if use_tls:
        ssl_kwargs["ssl_certfile"] = cert_path
        ssl_kwargs["ssl_keyfile"] = key_path
        log.info("HTTPS listening on %s:%s", http_host, http_port)
    else:
        log.info("HTTP (--dev) listening on %s:%s", http_host, http_port)

    config = uvicorn.Config(
        app,
        host=http_host,
        port=http_port,
        log_level="info",
        **ssl_kwargs,
    )
    http_server = uvicorn.Server(config)

    try:
        http_server.run()
    finally:
        server.stop(grace=2)
