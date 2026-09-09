"""In-memory auth sessions for UCS Start/GetAuthSession poll."""

from __future__ import annotations

import secrets
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, Optional


@dataclass
class AuthSession:
    session_code: str
    client_state: str
    created_at: float
    completed: bool = False
    user_token_jwt: Optional[str] = None
    expires_at: Optional[int] = None
    user_id: Optional[str] = None
    user_name: Optional[str] = None


class SessionStore:
    def __init__(self, ttl_seconds: int = 600):
        self.ttl_seconds = ttl_seconds
        self._lock = threading.Lock()
        self._sessions: Dict[str, AuthSession] = {}

    def create(self, client_state: str) -> AuthSession:
        self.purge_expired()
        code = secrets.token_urlsafe(24)
        sess = AuthSession(
            session_code=code,
            client_state=client_state,
            created_at=time.time(),
        )
        with self._lock:
            self._sessions[code] = sess
        return sess

    def get(self, session_code: str) -> Optional[AuthSession]:
        with self._lock:
            sess = self._sessions.get(session_code)
        if sess is None:
            return None
        if time.time() - sess.created_at > self.ttl_seconds:
            with self._lock:
                self._sessions.pop(session_code, None)
            return None
        return sess

    def complete(
        self,
        session_code: str,
        jwt_token: str,
        expires_at: int,
        user_id: str,
        user_name: str,
    ) -> bool:
        with self._lock:
            sess = self._sessions.get(session_code)
            if sess is None:
                return False
            sess.completed = True
            sess.user_token_jwt = jwt_token
            sess.expires_at = expires_at
            sess.user_id = user_id
            sess.user_name = user_name
            return True

    def purge_expired(self) -> None:
        now = time.time()
        with self._lock:
            dead = [
                k
                for k, v in self._sessions.items()
                if now - v.created_at > self.ttl_seconds
            ]
            for k in dead:
                del self._sessions[k]
