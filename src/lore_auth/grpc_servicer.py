"""gRPC epic_urc.UrcAuthApi servicer."""

from __future__ import annotations

import logging
from typing import Optional

import grpc
import jwt as pyjwt

from .jwt_util import TokenMinter
from .sessions import SessionStore
from .users import UsersConfig

log = logging.getLogger("lore_auth.grpc")

try:
    from lore_auth.generated import auth_api_pb2, auth_api_pb2_grpc
except ImportError:  # pragma: no cover - before gen_proto
    auth_api_pb2 = None  # type: ignore
    auth_api_pb2_grpc = None  # type: ignore


def _bearer_token(context: grpc.ServicerContext) -> Optional[str]:
    for key, value in context.invocation_metadata():
        if key.lower() == "authorization":
            val = value.decode("utf-8") if isinstance(value, bytes) else str(value)
            if val.lower().startswith("bearer "):
                return val[7:].strip()
            return val.strip()
    return None


class UrcAuthServicer:
    """Implements UrcAuthApi; unbound until attach() binds generated base."""

    def __init__(
        self,
        users: UsersConfig,
        sessions: SessionStore,
        minter: TokenMinter,
        public_base_url: str,
    ):
        self.users = users
        self.sessions = sessions
        self.minter = minter
        self.public_base_url = public_base_url.rstrip("/")

    def HealthCheck(self, request, context):
        return auth_api_pb2.HealthCheckResponse(status="ok")

    def StartAuthSession(self, request, context):
        client_state = request.client_state or ""
        sess = self.sessions.create(client_state=client_state)
        login_url = f"{self.public_base_url}/login?session={sess.session_code}"
        log.info("StartAuthSession session=%s…", sess.session_code[:8])
        return auth_api_pb2.StartAuthSessionResponse(
            session_code=sess.session_code,
            login_url=login_url,
        )

    def GetAuthSession(self, request, context):
        sess = self.sessions.get(request.session_code)
        if sess is None:
            context.abort(grpc.StatusCode.NOT_FOUND, "unknown or expired session")
        if sess.client_state != (request.client_state or ""):
            context.abort(grpc.StatusCode.INVALID_ARGUMENT, "client_state mismatch")
        if not sess.completed or not sess.user_token_jwt:
            return auth_api_pb2.GetAuthSessionResponse()
        return auth_api_pb2.GetAuthSessionResponse(
            user_token=auth_api_pb2.UserToken(
                user_token=sess.user_token_jwt,
                expires_at=int(sess.expires_at or 0),
                user_id=sess.user_id or "",
                user_name=sess.user_name or "",
            )
        )

    def ExchangeUserTokenForMultiresourceToken(self, request, context):
        bearer = _bearer_token(context)
        if not bearer:
            context.abort(grpc.StatusCode.UNAUTHENTICATED, "missing Bearer token")
        try:
            # Multi-aud tokens: verify signature/exp/iss manually if needed
            claims = pyjwt.decode(
                bearer,
                self.minter.public_key,
                algorithms=["RS256"],
                issuer=self.users.issuer or None,
                options={
                    "require": ["exp", "iat", "iss", "sub"],
                    "verify_aud": False,
                },
            )
            if self.users.audience:
                aud = claims.get("aud")
                auds = [aud] if isinstance(aud, str) else list(aud or [])
                if not any(a in auds for a in self.users.audience):
                    # allow if any audience element matches
                    context.abort(grpc.StatusCode.UNAUTHENTICATED, "audience mismatch")
        except pyjwt.PyJWTError as exc:
            context.abort(grpc.StatusCode.UNAUTHENTICATED, f"invalid token: {exc}")

        user = self.minter.user_from_claims(claims)
        if user is None or not user.enabled or user.is_expired():
            context.abort(grpc.StatusCode.PERMISSION_DENIED, "user not allowed")

        token = self.minter.mint_authz(user, list(request.resource_id))
        unverified = pyjwt.decode(token, options={"verify_signature": False})
        return auth_api_pb2.ExchangeUserTokenForMultiresourceTokenResponse(
            token=auth_api_pb2.UserToken(
                user_token=token,
                expires_at=int(unverified.get("exp") or 0),
                user_id=user.sub,
                user_name=user.name,
            )
        )

    def RefreshAuthSession(self, request, context):
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details("RefreshAuthSession not implemented")
        return auth_api_pb2.RefreshAuthSessionResponse()

    def VerifyUser(self, request, context):
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details("VerifyUser not implemented")
        return auth_api_pb2.VerifyUserResponse()

    def ExchangeExternalTokenForUserToken(self, request, context):
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details("ExchangeExternalTokenForUserToken not implemented")
        return auth_api_pb2.ExchangeExternalTokenForUserTokenResponse()

    def ExchangeAPIKeyForUserToken(self, request, context):
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details("ExchangeAPIKeyForUserToken not implemented")
        return auth_api_pb2.ExchangeAPIKeyForUserTokenResponse()

    def CheckUserPermission(self, request, context):
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details("CheckUserPermission not implemented")
        return auth_api_pb2.CheckUserPermissionResponse()

    def LookupUserPermissions(self, request, context):
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details("LookupUserPermissions not implemented")
        return auth_api_pb2.LookupUserPermissionsResponse()

    def GetUserInfo(self, request, context):
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details("GetUserInfo not implemented")
        return auth_api_pb2.GetUserInfoResponse()

    def GetUserId(self, request, context):
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details("GetUserId not implemented")
        return auth_api_pb2.GetUserIdResponse()

    def GetProviderUserId(self, request, context):
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details("GetProviderUserId not implemented")
        return auth_api_pb2.GetProviderUserIdResponse()


def build_servicer_class():
    """Return a class inheriting generated Servicer + our impl."""
    if auth_api_pb2_grpc is None:
        raise RuntimeError(
            "Generated stubs missing. Run: python scripts/gen_proto.py"
        )

    class BoundUrcAuthServicer(UrcAuthServicer, auth_api_pb2_grpc.UrcAuthApiServicer):
        pass

    return BoundUrcAuthServicer


def add_to_server(server, servicer) -> None:
    if auth_api_pb2_grpc is None:
        raise RuntimeError("Generated stubs missing. Run: python scripts/gen_proto.py")
    auth_api_pb2_grpc.add_UrcAuthApiServicer_to_server(servicer, server)
