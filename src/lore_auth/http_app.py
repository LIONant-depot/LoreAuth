"""HTTPS (or HTTP --dev) login page + JWKS endpoint."""

from __future__ import annotations

import html
import logging
from typing import Any, Callable, Optional
from urllib.parse import parse_qs

import jwt as pyjwt
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, Response
from starlette.routing import Route

from .jwt_util import TokenMinter
from .sessions import SessionStore
from .users import UsersConfig

log = logging.getLogger("lore_auth.http")

LOGIN_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>lore-auth login</title>
  <style>
    body {{ font-family: system-ui, sans-serif; max-width: 28rem; margin: 3rem auto; padding: 0 1rem; }}
    label {{ display: block; margin-top: 1rem; font-weight: 600; }}
    input {{ width: 100%; padding: 0.5rem; margin-top: 0.25rem; box-sizing: border-box; }}
    button {{ margin-top: 1.25rem; padding: 0.6rem 1.2rem; font-size: 1rem; cursor: pointer; }}
    .err {{ color: #b00020; margin-top: 1rem; }}
    .hint {{ color: #555; font-size: 0.9rem; }}
  </style>
</head>
<body>
  <h1>Lore access code</h1>
  <p class="hint">Enter the access code from your instructor. No password account.</p>
  {message}
  <form method="post" action="/login">
    <input type="hidden" name="session" value="{session}"/>
    <label>Username (optional)
      <input name="username" autocomplete="username" placeholder="leave blank if code alone"/>
    </label>
    <label>Access code
      <input name="secret" type="password" autocomplete="one-time-code" required autofocus/>
    </label>
    <button type="submit">Sign in</button>
  </form>
</body>
</html>
"""

DONE_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <title>Signed in</title>
  <style>
    body {{ font-family: system-ui, sans-serif; max-width: 28rem; margin: 3rem auto; padding: 0 1rem; }}
    .ok {{ color: #0a7a2f; }}
  </style>
</head>
<body>
  <h1 class="ok">Signed in</h1>
  <p>You can close this tab and return to LoreGUI. Polling should finish within a few seconds.</p>
</body>
</html>
"""


def create_app(
    users: UsersConfig,
    sessions: SessionStore,
    minter: TokenMinter,
    jwks: dict,
    reload_users: Optional[Callable[[], UsersConfig]] = None,
) -> Starlette:
    state: dict[str, Any] = {
        "users": users,
        "sessions": sessions,
        "minter": minter,
        "jwks": jwks,
        "reload_users": reload_users,
    }

    async def login_get(request: Request) -> Response:
        session = request.query_params.get("session") or ""
        if not session or sessions.get(session) is None:
            return HTMLResponse(
                LOGIN_HTML.format(
                    session=html.escape(session),
                    message='<p class="err">Invalid or expired session. Restart Connect in LoreGUI.</p>',
                ),
                status_code=400,
            )
        return HTMLResponse(
            LOGIN_HTML.format(session=html.escape(session), message="")
        )

    async def login_post(request: Request) -> Response:
        content_type = request.headers.get("content-type", "")
        if (
            "application/x-www-form-urlencoded" in content_type
            or "multipart/form-data" in content_type
        ):
            form = await request.form()
            session_code = str(form.get("session") or "")
            username = str(form.get("username") or "").strip() or None
            secret = str(form.get("secret") or "")
        else:
            body = (await request.body()).decode("utf-8", errors="replace")
            qs = parse_qs(body)
            session_code = (qs.get("session") or [""])[0]
            username = (qs.get("username") or [""])[0].strip() or None
            secret = (qs.get("secret") or [""])[0]

        sess = sessions.get(session_code)
        if sess is None:
            return HTMLResponse(
                LOGIN_HTML.format(
                    session=html.escape(session_code),
                    message='<p class="err">Invalid or expired session.</p>',
                ),
                status_code=400,
            )

        cfg = state["users"]
        if reload_users:
            try:
                cfg = reload_users()
                state["users"] = cfg
                minter.users = cfg
            except Exception as exc:  # noqa: BLE001
                log.warning("users reload failed: %s", exc)

        user = cfg.authenticate(secret=secret, username=username)
        if user is None:
            return HTMLResponse(
                LOGIN_HTML.format(
                    session=html.escape(session_code),
                    message='<p class="err">Invalid access code.</p>',
                ),
                status_code=401,
            )

        token = minter.mint_authn(user)
        unverified = pyjwt.decode(token, options={"verify_signature": False})
        exp = int(unverified["exp"])
        ok = sessions.complete(
            session_code,
            jwt_token=token,
            expires_at=exp,
            user_id=user.sub,
            user_name=user.name,
        )
        if not ok:
            return HTMLResponse(
                LOGIN_HTML.format(
                    session=html.escape(session_code),
                    message='<p class="err">Session vanished; retry Connect.</p>',
                ),
                status_code=400,
            )
        log.info(
            "login ok user=%s session=%s…",
            user.preferred_username,
            session_code[:8],
        )
        return HTMLResponse(DONE_HTML)

    async def jwks_get(_request: Request) -> JSONResponse:
        return JSONResponse(state["jwks"])

    async def health(_request: Request) -> JSONResponse:
        return JSONResponse({"status": "ok"})

    return Starlette(
        routes=[
            Route("/login", login_get, methods=["GET"]),
            Route("/login", login_post, methods=["POST"]),
            Route("/.well-known/jwks.json", jwks_get, methods=["GET"]),
            Route("/health", health, methods=["GET"]),
        ]
    )
