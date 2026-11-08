"""Parent login (password + TOTP), login throttling, and an OAuth 2.1 authorization-server provider
backed by SQLite, for use with the MCP SDK (Claude connects with Dynamic Client Registration + PKCE)."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import threading
import time

import pyotp
from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    AuthorizeError,
    RefreshToken,
    TokenError,
    construct_redirect_uri,
)
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken

from .db import DB

SCOPE = "parent"
ACCESS_TTL = 3600
REFRESH_TTL = 30 * 24 * 3600
CODE_TTL = 300
PENDING_TTL = 600
MAX_CLIENTS = 100


# ---------------------------------------------------------------- passwords + TOTP
def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    h = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)
    return "scrypt$" + base64.b64encode(salt).decode() + "$" + base64.b64encode(h).decode()


def verify_password(password: str, stored: str) -> bool:
    try:
        _, s, h = stored.split("$")
        salt, want = base64.b64decode(s), base64.b64decode(h)
        got = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)
        return hmac.compare_digest(got, want)
    except Exception:
        return False


_DUMMY_HASH = hash_password("dummy-for-timing")
_used_codes: dict[tuple[str, str], float] = {}      # (parent, code) -> expiry, to stop TOTP replay
_used_lock = threading.Lock()


def add_parent(db: DB, name: str, password: str) -> tuple[str, str]:
    """Create/replace a parent. Returns (totp_secret, otpauth_uri)."""
    if len(password) < 12:
        raise ValueError("Use a password of at least 12 characters.")
    secret = pyotp.random_base32()
    db.execute("INSERT INTO parents(name, pw_hash, totp_secret) VALUES (?,?,?) "
               "ON CONFLICT(name) DO UPDATE SET pw_hash=excluded.pw_hash, totp_secret=excluded.totp_secret",
               (name, hash_password(password), secret))
    return secret, pyotp.TOTP(secret).provisioning_uri(name=name, issuer_name="ScreenTime MCP")


def verify_login(db: DB, name: str, password: str, code: str) -> str | None:
    """Returns the canonical parent name on success. Always runs the password hash (timing)."""
    row = db.one("SELECT name, pw_hash, totp_secret FROM parents WHERE name=?", ((name or "").strip(),))
    pw_ok = verify_password(password or "", row["pw_hash"] if row else _DUMMY_HASH)
    code = (code or "").strip().replace(" ", "")
    totp_ok = False
    if row and code.isdigit() and len(code) == 6:
        totp_ok = pyotp.TOTP(row["totp_secret"]).verify(code, valid_window=1)
    if not (row and pw_ok and totp_ok):
        return None
    now = time.time()
    with _used_lock:
        for k in [k for k, exp in _used_codes.items() if exp < now]:
            del _used_codes[k]
        if (row["name"], code) in _used_codes:
            return None                                   # replayed code
        _used_codes[(row["name"], code)] = now + 120
    return row["name"]


class LoginThrottle:
    """Per-IP and global failure limits (15 min window). In-memory: resets on restart, which is acceptable."""

    def __init__(self, per_ip=5, global_limit=20, window=900):
        self.per_ip, self.global_limit, self.window = per_ip, global_limit, window
        self._fails: list[tuple[float, str]] = []
        self._lock = threading.Lock()

    def _prune(self, now):
        self._fails = [(t, ip) for t, ip in self._fails if now - t < self.window]

    def blocked(self, ip: str) -> bool:
        now = time.time()
        with self._lock:
            self._prune(now)
            return len(self._fails) >= self.global_limit or sum(1 for _, i in self._fails if i == ip) >= self.per_ip

    def fail(self, ip: str):
        with self._lock:
            self._fails.append((time.time(), ip))

    def reset(self):
        with self._lock:
            self._fails.clear()


# ---------------------------------------------------------------- OAuth provider
def _h(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


class SqliteOAuthProvider:
    def __init__(self, db: DB, base_url: str):
        self.db = db
        self.base_url = base_url.rstrip("/")

    # --- clients (Dynamic Client Registration)
    async def get_client(self, client_id: str):
        row = self.db.one("SELECT json FROM oauth_clients WHERE client_id=?", (client_id,))
        return OAuthClientInformationFull.model_validate_json(row["json"]) if row else None

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        self.db.execute("INSERT OR REPLACE INTO oauth_clients(client_id, created_at, json) VALUES (?,?,?)",
                        (client_info.client_id, int(time.time()), client_info.model_dump_json()))
        self.db.execute("DELETE FROM oauth_clients WHERE client_id NOT IN "
                        "(SELECT client_id FROM oauth_clients ORDER BY created_at DESC LIMIT ?)", (MAX_CLIENTS,))

    # --- authorization: hand off to our login page, which finishes via complete_authorization()
    async def authorize(self, client: OAuthClientInformationFull, params: AuthorizationParams) -> str:
        req = secrets.token_urlsafe(24)
        self.db.execute("DELETE FROM oauth_pending WHERE expires_at < ?", (int(time.time()),))
        self.db.execute("INSERT INTO oauth_pending(req_id, expires_at, json) VALUES (?,?,?)",
                        (req, int(time.time()) + PENDING_TTL,
                         json.dumps({"client_id": client.client_id, "params": params.model_dump(mode="json")})))
        return f"{self.base_url}/login?req={req}"

    def pending(self, req_id: str) -> dict | None:
        row = self.db.one("SELECT expires_at, json FROM oauth_pending WHERE req_id=?", (req_id,))
        if not row or row["expires_at"] < time.time():
            return None
        return json.loads(row["json"])

    def complete_authorization(self, req_id: str, parent: str) -> str:
        """Called after a successful login. Returns the redirect URL back to the client."""
        data = self.pending(req_id)
        if data is None:
            raise AuthorizeError("invalid_request", "Login session expired - start again from Claude.")
        self.db.execute("DELETE FROM oauth_pending WHERE req_id=?", (req_id,))
        p = AuthorizationParams.model_validate(data["params"])
        code = secrets.token_urlsafe(32)
        ac = AuthorizationCode(code=code, scopes=p.scopes or [SCOPE], expires_at=time.time() + CODE_TTL,
                               client_id=data["client_id"], code_challenge=p.code_challenge,
                               redirect_uri=p.redirect_uri, redirect_uri_provided_explicitly=p.redirect_uri_provided_explicitly,
                               resource=p.resource, subject=parent)
        self.db.execute("INSERT INTO oauth_codes(hash, expires_at, json) VALUES (?,?,?)",
                        (_h(code), int(ac.expires_at), ac.model_dump_json(exclude={"code"})))
        return construct_redirect_uri(str(p.redirect_uri), code=code, state=p.state)

    async def load_authorization_code(self, client, authorization_code: str):
        row = self.db.one("SELECT json, expires_at FROM oauth_codes WHERE hash=?", (_h(authorization_code),))
        if not row or row["expires_at"] < time.time():
            return None
        ac = AuthorizationCode.model_validate({**json.loads(row["json"]), "code": authorization_code})
        return ac if ac.client_id == client.client_id else None

    def _issue(self, client_id: str, scopes: list[str], resource, subject) -> OAuthToken:
        access, refresh, pair = secrets.token_urlsafe(32), secrets.token_urlsafe(32), secrets.token_urlsafe(12)
        now = int(time.time())
        at = AccessToken(token=access, client_id=client_id, scopes=scopes, expires_at=now + ACCESS_TTL, resource=resource, subject=subject)
        rt = RefreshToken(token=refresh, client_id=client_id, scopes=scopes, expires_at=now + REFRESH_TTL, resource=resource, subject=subject)
        self.db.execute("DELETE FROM oauth_tokens WHERE expires_at < ?", (now,))
        self.db.execute("INSERT INTO oauth_tokens(hash, kind, pair_id, expires_at, json) VALUES (?,?,?,?,?)",
                        (_h(access), "access", pair, at.expires_at, at.model_dump_json(exclude={"token"})))
        self.db.execute("INSERT INTO oauth_tokens(hash, kind, pair_id, expires_at, json) VALUES (?,?,?,?,?)",
                        (_h(refresh), "refresh", pair, rt.expires_at, rt.model_dump_json(exclude={"token"})))
        return OAuthToken(access_token=access, expires_in=ACCESS_TTL, scope=" ".join(scopes), refresh_token=refresh)

    async def exchange_authorization_code(self, client, authorization_code) -> OAuthToken:
        gone = self.db.execute("DELETE FROM oauth_codes WHERE hash=?", (_h(authorization_code.code),)).rowcount
        if gone != 1:                                         # already used -> single use only
            raise TokenError("invalid_grant", "authorization code already used")
        return self._issue(client.client_id, authorization_code.scopes, authorization_code.resource, authorization_code.subject)

    async def load_refresh_token(self, client, refresh_token: str):
        row = self.db.one("SELECT json, expires_at FROM oauth_tokens WHERE hash=? AND kind='refresh'", (_h(refresh_token),))
        if not row or (row["expires_at"] or 0) < time.time():
            return None
        rt = RefreshToken.model_validate({**json.loads(row["json"]), "token": refresh_token})
        return rt if rt.client_id == client.client_id else None

    async def exchange_refresh_token(self, client, refresh_token, scopes: list[str]) -> OAuthToken:
        if scopes and not set(scopes) <= set(refresh_token.scopes):
            raise TokenError("invalid_scope", "scope exceeds the original grant")
        row = self.db.one("SELECT pair_id FROM oauth_tokens WHERE hash=?", (_h(refresh_token.token),))
        if not row:
            raise TokenError("invalid_grant", "refresh token revoked")
        self.db.execute("DELETE FROM oauth_tokens WHERE pair_id=?", (row["pair_id"],))        # rotate both
        return self._issue(client.client_id, scopes or refresh_token.scopes, refresh_token.resource, refresh_token.subject)

    async def load_access_token(self, token: str):
        row = self.db.one("SELECT json, expires_at FROM oauth_tokens WHERE hash=? AND kind='access'", (_h(token),))
        if not row or (row["expires_at"] or 0) < time.time():
            return None
        return AccessToken.model_validate({**json.loads(row["json"]), "token": token})

    async def revoke_token(self, token) -> None:
        row = self.db.one("SELECT pair_id FROM oauth_tokens WHERE hash=?", (_h(token.token),))
        if row:
            self.db.execute("DELETE FROM oauth_tokens WHERE pair_id=?", (row["pair_id"],))
