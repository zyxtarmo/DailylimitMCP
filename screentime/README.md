# Screen-time control: Claude connector + PC agent

Parents manage children's Windows screen time from the Claude app (phone, web, desktop).

```
Claude app ──MCP over HTTPS + OAuth──►  server (VPS, Docker, Caddy TLS, SQLite)
                                              ▲
                              every minute, outbound only (device key)
                                              │
                 Windows PC: DailyLimit.ps1 (SYSTEM scheduled task) ── enforces locally, works offline
```

* `server/` – one ASGI app: MCP server, parent login (password + authenticator code), agent sync API.
* `agent/`  – `DailyLimit.ps1` (enforcer) and `Install-DailyLimit.ps1` (installer) for each Windows PC.

## What you can ask Claude

"How much screen time has Emma used today?" · "Lock Emma for 30 minutes, it's dinner." · "Emma may have 15 extra
minutes today for homework." · "Set Jonas's weekday limit to 90 minutes and weekday hours to 15:00-20:00."

Tools: `list_children`, `get_usage`, `set_schedule`, `add_bonus`, `lock_child`, `unlock_child`, `remove_child`,
`device_status`, `recent_activity`.

**Guardrails.** Anything that *loosens* limits (more minutes, wider hours, unlock, remove) is refused unless the call
carries `confirm=true`; Claude is instructed to pass that only after you explicitly agree. Bonus time has a per-day
cap (`MAX_BONUS_PER_DAY`) and needs a reason. Tightening (lock, fewer minutes, shorter hours) is always immediate.
Every change is written to an audit log (`recent_activity`). Note the confirm step is enforced by the tool contract and
Claude's behaviour, not by a second factor – the daily cap is the hard backstop.

## 1. Deploy the server (a small VPS, ~1 GB RAM is plenty)

Needs a domain name pointing at the VPS, and Docker with the compose plugin.

```bash
cd server
cp .env.example .env && nano .env          # DOMAIN, BASE_URL, TIMEZONE (must match the PCs!)
docker compose up -d --build
docker compose exec app python -m app.admin add-parent mom     # password (12+ chars); prints authenticator secret
docker compose exec app python -m app.admin add-device pc-home # prints the device key ONCE
```

Add the printed secret to an authenticator app (manual entry). Add a second parent the same way.
Check: `https://<domain>/healthz` returns `ok`.

Backups: the whole state is one SQLite file in the `data` volume
(`docker compose exec app python -c "import sqlite3;sqlite3.connect('/data/screentime.db').execute(\"vacuum into '/data/backup.db'\")"`).

## 2. Connect Claude

Claude on the web (claude.ai) → Settings → Connectors → Add custom connector → URL `https://<domain>/mcp` → Connect.
A sign-in page on your server opens: parent name, password, authenticator code. After that the connector is available in
the Claude mobile app on the same account (mobile can use connectors but cannot add new ones). A second parent adds the
connector on their own Claude account. Custom connectors need a Claude plan that supports them (the free plan allows one).

## 3. Install the agent on each PC (elevated PowerShell)

Children must use **standard (non-admin) local accounts**, named exactly like the Windows account.

```powershell
.\Install-DailyLimit.ps1 -Server https://<domain> -DeviceId pc-home -DeviceKey <key>
```

Then tell Claude: *"Add child kid1 with 90 minutes on weekdays, 150 at weekends, weekday hours 15:00-20:00."*
Within a minute the PC picks it up (`& "$env:ProgramData\DailyLimit\DailyLimit.ps1" -Status`).

* The PC polls once a minute; parent changes take effect within ~1–2 minutes.
* **Offline:** the last policy is cached and keeps being enforced; usage is uploaded when the connection returns.
  `device_status` shows PCs that stopped checking in.
* **Clock/time-zone tampering:** while syncs succeed, the allowed-hours window uses the *server's* wall clock, so
  changing the PC's clock or time zone doesn't help.
* Limits are **per PC** (a child with two PCs gets the limit on each). Usage from all PCs is summed in reports.
* Without a server the installer still works in local mode (`-Add kid1 ...`).

## Security notes

* The only public surface is HTTPS. `/mcp` needs an OAuth token; `/agent/v1/sync` needs a per-PC key;
  the login page needs password **and** TOTP, with per-IP and global throttling and TOTP replay protection.
  Dynamic client registration is open by design (required by Claude) but grants nothing without the parent login.
* The agent folder `C:\ProgramData\DailyLimit` is locked to SYSTEM/Administrators (it runs as SYSTEM – a child who
  could write there could escalate). Don't loosen that ACL; keep children non-admin. Rotate a PC's key by running
  `add-device` again with the same id, then re-run the installer with the new key.
* Known gaps: someone with admin rights, boot media, or an unmanaged second PC/phone can bypass any PC-side control;
  protect the BIOS/boot order. A PC that has never synced uses its own clock.

## Tests

```bash
cd server && python -m venv .venv && . .venv/bin/activate && pip install -r requirements-dev.txt
python -m pytest tests/test_core.py -q        # policy rules + guards
python tests/e2e.py                            # OAuth (DCR, login, PKCE, refresh) + MCP tools + agent API
# agent logic on Linux (needs PowerShell 7: pwsh), fake session API against the real server:
python tests/agent_e2e.py /path/to/pwsh ../agent/DailyLimit.ps1
```

**Verification status:** server, OAuth flow, MCP tools, and agent logic are covered by the tests above. Not verified on a
real Windows machine: the session API calls (WTS), the scheduled task, and Windows PowerShell 5.1 specifics, and the
Docker image was not built in the authoring environment. Do a first run with a 3-minute limit on a test account
(`set_schedule ... weekday_minutes=3 weekend_minutes=3`) before relying on it.
