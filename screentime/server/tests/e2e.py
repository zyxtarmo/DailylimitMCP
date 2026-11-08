"""End-to-end: real uvicorn server -> Dynamic Client Registration -> parent login (password+TOTP) -> PKCE token
-> MCP tool calls over Streamable HTTP -> agent sync.  Run:  python tests/e2e.py"""
import asyncio
import base64
import hashlib
import os
import secrets
import subprocess
import sys
import tempfile
import time
from urllib.parse import parse_qs, urlparse

import httpx
import httpx2
import pyotp

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
PORT = 8765
BASE = f"http://localhost:{PORT}"
tmp = tempfile.mkdtemp()
env = {**os.environ, "DB_PATH": os.path.join(tmp, "t.db"), "BASE_URL": BASE, "TIMEZONE": "Europe/Tallinn"}
os.environ.update(env)

from app import auth, core  # noqa: E402
from app.db import DB  # noqa: E402

db = DB(env["DB_PATH"])
secret, _ = auth.add_parent(db, "mom", "correct horse battery")
device_key = core.create_device(db, "pc-home")

proc = subprocess.Popen([sys.executable, "-m", "uvicorn", "app.main:app", "--port", str(PORT), "--log-level", "warning"],
                        cwd=ROOT, env=env)
ok = True


def check(label, cond, extra=""):
    global ok
    print(("PASS " if cond else "FAIL ") + label, extra if not cond else "")
    ok &= bool(cond)


try:
    for _ in range(50):
        try:
            if httpx.get(BASE + "/healthz").status_code == 200:
                break
        except Exception:
            time.sleep(0.2)

    # --- discovery + unauthenticated access is refused
    r = httpx.post(BASE + "/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
                   headers={"Accept": "application/json, text/event-stream"})
    check("unauthenticated /mcp -> 401", r.status_code == 401, r.status_code)
    check("401 points at resource metadata", "resource_metadata" in r.headers.get("www-authenticate", ""), r.headers)
    prm = httpx.get(BASE + "/.well-known/oauth-protected-resource/mcp").json()
    asm = httpx.get(BASE + "/.well-known/oauth-authorization-server").json()
    check("metadata advertises registration + S256", "registration_endpoint" in asm and "S256" in asm["code_challenge_methods_supported"], asm)

    # --- Dynamic Client Registration (what Claude does)
    redirect = "https://claude.ai/api/mcp/auth_callback"
    reg = httpx.post(BASE + "/register", json={"client_name": "Claude", "redirect_uris": [redirect],
                                               "grant_types": ["authorization_code", "refresh_token"],
                                               "response_types": ["code"], "token_endpoint_auth_method": "none"})
    check("DCR works", reg.status_code in (200, 201), reg.text)
    cid = reg.json()["client_id"]

    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    q = {"response_type": "code", "client_id": cid, "redirect_uri": redirect, "code_challenge": challenge,
         "code_challenge_method": "S256", "state": "xyz", "scope": "parent"}
    a = httpx.get(BASE + "/authorize", params=q, follow_redirects=False)
    check("/authorize redirects to our login", a.status_code in (302, 307) and "/login?req=" in a.headers.get("location", ""), a.text)
    login_url = a.headers["location"]
    req = parse_qs(urlparse(login_url).query)["req"][0]
    page = httpx.get(login_url)
    check("login page renders client + redirect host", page.status_code == 200 and "claude.ai" in page.text and "Claude" in page.text)

    # wrong password / wrong code / right
    bad = httpx.post(BASE + "/login", data={"req": req, "username": "mom", "password": "nope-nope-nope", "code": pyotp.TOTP(secret).now()})
    check("wrong password rejected", bad.status_code == 401)
    bad = httpx.post(BASE + "/login", data={"req": req, "username": "mom", "password": "correct horse battery", "code": "000000"})
    check("wrong TOTP rejected", bad.status_code == 401)
    good = httpx.post(BASE + "/login", data={"req": req, "username": "mom", "password": "correct horse battery", "code": pyotp.TOTP(secret).now()},
                      follow_redirects=False)
    check("good login redirects to client with code+state", good.status_code == 302 and good.headers["location"].startswith(redirect)
          and "state=xyz" in good.headers["location"], good.text)
    code = parse_qs(urlparse(good.headers["location"]).query)["code"][0]
    again = httpx.post(BASE + "/login", data={"req": req, "username": "mom", "password": "correct horse battery", "code": pyotp.TOTP(secret).now()})
    check("login req is single-use", again.status_code == 400)

    # --- token (PKCE): wrong verifier fails, right works, code is single-use
    t_bad = httpx.post(BASE + "/token", data={"grant_type": "authorization_code", "code": code, "redirect_uri": redirect,
                                              "client_id": cid, "code_verifier": secrets.token_urlsafe(48)})
    check("wrong PKCE verifier rejected", t_bad.status_code == 400, t_bad.text)
    t = httpx.post(BASE + "/token", data={"grant_type": "authorization_code", "code": code, "redirect_uri": redirect,
                                          "client_id": cid, "code_verifier": verifier})
    check("token exchange works", t.status_code == 200 and "access_token" in t.json(), t.text)
    tok = t.json()
    t2 = httpx.post(BASE + "/token", data={"grant_type": "authorization_code", "code": code, "redirect_uri": redirect,
                                           "client_id": cid, "code_verifier": verifier})
    check("auth code is single-use", t2.status_code == 400)

    # --- refresh rotation
    rf = httpx.post(BASE + "/token", data={"grant_type": "refresh_token", "refresh_token": tok["refresh_token"], "client_id": cid})
    check("refresh works + rotates", rf.status_code == 200 and rf.json()["access_token"] != tok["access_token"], rf.text)
    rf2 = httpx.post(BASE + "/token", data={"grant_type": "refresh_token", "refresh_token": tok["refresh_token"], "client_id": cid})
    check("old refresh token rejected", rf2.status_code == 400)
    access = rf.json()["access_token"]
    check("old access token revoked by rotation",
          httpx.post(BASE + "/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
                     headers={"Authorization": "Bearer " + tok["access_token"], "Accept": "application/json, text/event-stream"}).status_code == 401)

    # --- MCP tools over Streamable HTTP with the token
    from mcp.client import Client
    from mcp.client.streamable_http import streamable_http_client

    async def mcp_part():
        async with httpx2.AsyncClient(headers={"Authorization": f"Bearer {access}"}, timeout=30) as hc:
            if True:
                async with Client(streamable_http_client(BASE + "/mcp", http_client=hc)) as c:
                    tools = {t.name for t in (await c.list_tools()).tools}
                    check("tools listed", {"add_bonus", "set_schedule", "lock_child", "get_usage", "device_status"} <= tools, tools)

                    async def call(name, **args):
                        res = await c.call_tool(name, args)
                        sc = getattr(res, "structured_content", None) or getattr(res, "structuredContent", None)
                        if sc:
                            return sc
                        import json as _j
                        return _j.loads(res.content[0].text)

                    r = await call("set_schedule", child="kid1", weekday_minutes=90, weekend_minutes=150, weekday_hours="15:00-20:00")
                    check("create child", r.get("ok"), r)
                    r = await call("set_schedule", child="kid1", weekday_minutes=200)
                    check("loosening w/o confirm refused", r.get("ok") is False and r.get("needs_confirmation"), r)
                    r = await call("add_bonus", child="kid1", minutes=30, reason="homework")
                    check("bonus w/o confirm refused", r.get("needs_confirmation"), r)
                    r = await call("add_bonus", child="kid1", minutes=30, reason="homework", confirm=True)
                    check("bonus with confirm ok", r.get("ok") and r.get("bonus_today") == 30, r)
                    r = await call("lock_child", child="kid1", minutes=15, reason="dinner")
                    check("lock ok", r.get("ok"), r)
                    r = await call("recent_activity", limit=5)
                    check("audit records actor 'mom'", any(e["actor"] == "mom" for e in r.get("events", [])), r)

    asyncio.run(mcp_part())

    # --- agent sync
    h = {"X-Device-Id": "pc-home", "Authorization": f"Bearer {device_key}"}
    day = core.day_key(core.Config())
    s = httpx.post(BASE + "/agent/v1/sync", json={"day": day, "agent_version": "2", "users": [{"name": "kid1", "minutes": 42.5}]}, headers=h)
    check("agent sync ok", s.status_code == 200, s.text)
    u = {x["Name"]: x for x in s.json()["Users"]}["kid1"]
    check("agent sees bonus + lock + hours", u["Bonus"] == 30 and u["LockedUntil"] > s.json()["server_time"] and u["WeekdayHours"] == "15:00-20:00", u)
    check("agent bad key -> 401", httpx.post(BASE + "/agent/v1/sync", json={"day": day}, headers={**h, "Authorization": "Bearer nope"}).status_code == 401)
    check("agent no auth -> 401", httpx.post(BASE + "/agent/v1/sync", json={"day": day}).status_code == 401)

    # --- login throttle
    for _ in range(6):
        httpx.post(BASE + "/login", data={"req": "x", "username": "mom", "password": "bad-bad-bad-bad", "code": "111111"})
    r = httpx.post(BASE + "/login", data={"req": "x", "username": "mom", "password": "bad", "code": "1"})
    check("login throttled after repeated failures", r.status_code in (400, 429))
finally:
    proc.terminate()
    proc.wait(timeout=10)
print("\nALL PASSED" if ok else "\nSOME FAILED")
sys.exit(0 if ok else 1)
