"""Business logic: policy, bonuses, locks, usage, agent sync, audit. No HTTP / MCP in here."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import time
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

from .db import DB

NAME_RE = re.compile(r'^[^\\/:*?"<>|@\s][^\\/:*?"<>|@]{0,31}$')   # Windows-local-account friendly
HOURS_RE = re.compile(r"^(\d{2}):(\d{2})-(\d{2}):(\d{2})$")
DAY_RE = re.compile(r"^\d{8}$")


class PolicyError(Exception):
    """User-facing error (shown to the parent through the MCP tool)."""


class NeedsConfirmation(PolicyError):
    """The change loosens limits; the parent must explicitly confirm."""


class Config:
    def __init__(self):
        self.tz = ZoneInfo(os.environ.get("TIMEZONE", "Europe/Tallinn"))
        self.max_bonus_per_day = int(os.environ.get("MAX_BONUS_PER_DAY", "60"))
        self.default_weekday = int(os.environ.get("DEFAULT_WEEKDAY_MINUTES", "120"))
        self.default_weekend = int(os.environ.get("DEFAULT_WEEKEND_MINUTES", "180"))
        self.stale_after_s = int(os.environ.get("STALE_AFTER_SECONDS", "300"))


# ---------------------------------------------------------------- time helpers
def now_ts() -> int:
    return int(time.time())


def local_dt(cfg: Config, ts: int | None = None) -> datetime:
    return datetime.fromtimestamp(ts if ts is not None else now_ts(), cfg.tz)


def day_key(cfg: Config, ts: int | None = None) -> str:
    return local_dt(cfg, ts).strftime("%Y%m%d")


def is_weekend_key(day: str) -> bool:
    return datetime.strptime(day, "%Y%m%d").weekday() >= 5


# ---------------------------------------------------------------- validation
def check_name(name: str) -> str:
    name = (name or "").strip()
    if not NAME_RE.match(name):
        raise PolicyError("Child name must be the Windows account name (1-32 chars, no \\ / : * ? \" < > | @).")
    return name


def parse_hours(spec: str | None) -> tuple[int, int] | None:
    """'08:00-20:00' -> (480, 1200). '' / None -> None (unrestricted). End may be 24:00."""
    if spec is None or spec.strip() == "":
        return None
    m = HOURS_RE.match(spec.strip())
    if not m:
        raise PolicyError(f"Hours must look like 08:00-20:00 (24h, same day), got '{spec}'.")
    h1, m1, h2, m2 = (int(x) for x in m.groups())
    if m1 > 59 or m2 > 59 or h1 > 23 or h2 > 24 or (h2 == 24 and m2 != 0):
        raise PolicyError(f"Invalid time in '{spec}'.")
    a, b = h1 * 60 + m1, h2 * 60 + m2
    if a >= b:
        raise PolicyError(f"Hours '{spec}' must end after they start (windows cannot cross midnight).")
    return a, b


def norm_hours(spec: str | None) -> str | None:
    w = parse_hours(spec)
    if w is None:
        return None
    return "{:02d}:{:02d}-{:02d}:{:02d}".format(w[0] // 60, w[0] % 60, w[1] // 60, w[1] % 60)


def check_minutes(v: int, label: str) -> int:
    if not isinstance(v, int) or isinstance(v, bool) or v < 0 or v > 1440:
        raise PolicyError(f"{label} must be a whole number of minutes between 0 and 1440.")
    return v


# ---------------------------------------------------------------- audit
def audit(db: DB, actor: str, action: str, details: dict | None = None) -> None:
    db.execute("INSERT INTO audit(ts, actor, action, details) VALUES (?,?,?,?)",
               (now_ts(), actor, action, json.dumps(details or {}, ensure_ascii=False)))


def recent_audit(db: DB, limit: int = 20) -> list[dict]:
    rows = db.all("SELECT ts, actor, action, details FROM audit ORDER BY id DESC LIMIT ?", (max(1, min(limit, 100)),))
    return [{"time": datetime.fromtimestamp(r["ts"]).isoformat(timespec="seconds"), "actor": r["actor"],
             "action": r["action"], "details": json.loads(r["details"] or "{}")} for r in rows]


# ---------------------------------------------------------------- children / policy
def get_child(db: DB, name: str):
    row = db.one("SELECT * FROM children WHERE name=?", (name,))
    if not row:
        known = ", ".join(r["name"] for r in db.all("SELECT name FROM children ORDER BY name")) or "none yet"
        raise PolicyError(f"Unknown child '{name}'. Known: {known}.")
    return row


def loosening_reasons(old, new: dict) -> list[str]:
    """Why `new` (dict of final values) is more permissive than the stored row `old`."""
    out = []
    for kind in ("weekday", "weekend"):
        if new[kind] > old[kind]:
            out.append(f"{kind} minutes {old[kind]} -> {new[kind]}")
        o, n = parse_hours(old[f"{kind}_hours"]), parse_hours(new[f"{kind}_hours"])
        if o is not None and (n is None or n[0] < o[0] or n[1] > o[1]):
            out.append(f"{kind} hours {norm_hours(old[f'{kind}_hours'])} -> {norm_hours(new[f'{kind}_hours']) or 'unrestricted'}")
    return out


def set_schedule(db: DB, cfg: Config, actor: str, name: str, *, weekday_minutes=None, weekend_minutes=None,
                 weekday_hours=None, weekend_hours=None, confirm=False) -> dict:
    """None = leave unchanged. For hours, '' / 'none' / 'any' = remove the restriction."""
    name = check_name(name)

    def hours_arg(v):
        if v is None:
            return "KEEP"
        return None if v.strip().lower() in ("", "none", "any", "unrestricted") else norm_hours(v)

    row = db.one("SELECT * FROM children WHERE name=?", (name,))
    if row is None:
        final = {"weekday": check_minutes(weekday_minutes if weekday_minutes is not None else cfg.default_weekday, "weekday_minutes"),
                 "weekend": check_minutes(weekend_minutes if weekend_minutes is not None else cfg.default_weekend, "weekend_minutes")}
        for k, v in (("weekday_hours", weekday_hours), ("weekend_hours", weekend_hours)):
            h = hours_arg(v)
            final[k] = None if h == "KEEP" else h
        with db.tx():
            db.execute("INSERT INTO children(name, weekday, weekend, weekday_hours, weekend_hours, updated_at) VALUES (?,?,?,?,?,?)",
                       (name, final["weekday"], final["weekend"], final["weekday_hours"], final["weekend_hours"], now_ts()))
            audit(db, actor, "child_created", {"child": name, **final})
        return {"child": name, "created": True, **final}

    final = {"weekday": row["weekday"], "weekend": row["weekend"],
             "weekday_hours": row["weekday_hours"], "weekend_hours": row["weekend_hours"]}
    if weekday_minutes is not None:
        final["weekday"] = check_minutes(weekday_minutes, "weekday_minutes")
    if weekend_minutes is not None:
        final["weekend"] = check_minutes(weekend_minutes, "weekend_minutes")
    for k, v in (("weekday_hours", weekday_hours), ("weekend_hours", weekend_hours)):
        h = hours_arg(v)
        if h != "KEEP":
            final[k] = h
    reasons = loosening_reasons(row, final)
    if reasons and not confirm:
        raise NeedsConfirmation("This LOOSENS limits (" + "; ".join(reasons) + "). Ask the parent to confirm explicitly, "
                                "then call again with confirm=true.")
    with db.tx():
        db.execute("UPDATE children SET weekday=?, weekend=?, weekday_hours=?, weekend_hours=?, updated_at=? WHERE name=?",
                   (final["weekday"], final["weekend"], final["weekday_hours"], final["weekend_hours"], now_ts(), name))
        audit(db, actor, "schedule_set", {"child": name, **final, "loosened": reasons})
    return {"child": row["name"], "created": False, **final}


def remove_child(db: DB, actor: str, name: str, confirm: bool) -> dict:
    row = get_child(db, name)
    if not confirm:
        raise NeedsConfirmation(f"Removing {row['name']} removes ALL limits for that account. Ask the parent to confirm, then call with confirm=true.")
    with db.tx():
        db.execute("DELETE FROM children WHERE name=?", (name,))
        db.execute("DELETE FROM bonuses WHERE child=?", (name,))
        audit(db, actor, "child_removed", {"child": row["name"]})
    return {"removed": row["name"]}


def effective_limit(db: DB, row, day: str) -> int:
    base = row["weekend"] if is_weekend_key(day) else row["weekday"]
    b = db.one("SELECT minutes FROM bonuses WHERE child=? AND day=?", (row["name"], day))
    return max(0, base + (b["minutes"] if b else 0))


def add_bonus(db: DB, cfg: Config, actor: str, name: str, minutes: int, reason: str, confirm=False) -> dict:
    row = get_child(db, name)
    day = day_key(cfg)
    if not isinstance(minutes, int) or isinstance(minutes, bool) or minutes == 0 or abs(minutes) > 1440:
        raise PolicyError("minutes must be a non-zero whole number (negative removes time).")
    cur = db.one("SELECT minutes FROM bonuses WHERE child=? AND day=?", (row["name"], day))
    cur_b = cur["minutes"] if cur else 0
    new_b = cur_b + minutes
    if minutes > 0:
        if not (reason or "").strip():
            raise PolicyError("A reason is required when adding time.")
        if new_b > cfg.max_bonus_per_day:
            raise PolicyError(f"Daily bonus cap is {cfg.max_bonus_per_day} min per child; {row['name']} already has {cur_b} today.")
        if not confirm:
            raise NeedsConfirmation(f"This ADDS {minutes} min of screen time for {row['name']} today. Ask the parent to confirm, "
                                    "then call again with confirm=true.")
    else:
        base = row["weekend"] if is_weekend_key(day) else row["weekday"]
        new_b = max(new_b, -base)
    with db.tx():
        db.execute("INSERT INTO bonuses(child, day, minutes) VALUES (?,?,?) ON CONFLICT(child, day) DO UPDATE SET minutes=excluded.minutes",
                   (row["name"], day, new_b))
        audit(db, actor, "bonus", {"child": row["name"], "delta": minutes, "total_today": new_b, "reason": reason})
    return {"child": row["name"], "bonus_today": new_b, "limit_today": effective_limit(db, row, day)}


def lock(db: DB, actor: str, name: str, minutes: int, reason: str = "") -> dict:
    row = get_child(db, name)
    if not isinstance(minutes, int) or isinstance(minutes, bool) or minutes < 1 or minutes > 1440:
        raise PolicyError("minutes must be between 1 and 1440.")
    until = max(row["locked_until"], now_ts() + minutes * 60)      # a lock can only be extended here
    with db.tx():
        db.execute("UPDATE children SET locked_until=?, updated_at=? WHERE name=?", (until, now_ts(), row["name"]))
        audit(db, actor, "lock", {"child": row["name"], "minutes": minutes, "until": until, "reason": reason})
    return {"child": row["name"], "locked_until": datetime.fromtimestamp(until).isoformat(timespec="seconds")}


def unlock(db: DB, actor: str, name: str, confirm=False) -> dict:
    row = get_child(db, name)
    if not confirm:
        raise NeedsConfirmation(f"This LIFTS the lock on {row['name']}. Ask the parent to confirm, then call with confirm=true.")
    with db.tx():
        db.execute("UPDATE children SET locked_until=0, updated_at=? WHERE name=?", (now_ts(), row["name"]))
        audit(db, actor, "unlock", {"child": row["name"]})
    return {"child": row["name"], "locked_until": None}


# ---------------------------------------------------------------- reporting
def list_children(db: DB, cfg: Config) -> list[dict]:
    day = day_key(cfg)
    out = []
    for r in db.all("SELECT * FROM children ORDER BY name"):
        used = db.one("SELECT COALESCE(SUM(minutes),0) AS m FROM usage WHERE child=? AND day=?", (r["name"], day))["m"]
        locked = r["locked_until"] if r["locked_until"] > now_ts() else None
        out.append({"child": r["name"], "weekday_minutes": r["weekday"], "weekend_minutes": r["weekend"],
                    "weekday_hours": r["weekday_hours"] or "any time", "weekend_hours": r["weekend_hours"] or "any time",
                    "limit_today": effective_limit(db, r, day), "used_today": round(used, 1),
                    "locked_until": datetime.fromtimestamp(locked).isoformat(timespec="seconds") if locked else None})
    return out


def get_usage(db: DB, cfg: Config, name: str | None = None, days: int = 1) -> list[dict]:
    days = max(1, min(int(days), 31))
    rows = [get_child(db, name)] if name else db.all("SELECT * FROM children ORDER BY name")
    out = []
    for r in rows:
        per_day = []
        for i in range(days):
            d = (local_dt(cfg) - timedelta(days=i)).strftime("%Y%m%d")
            devs = db.all("SELECT device, minutes FROM usage WHERE child=? AND day=? ORDER BY device", (r["name"], d))
            per_day.append({"day": f"{d[:4]}-{d[4:6]}-{d[6:]}", "used_minutes": round(sum(x["minutes"] for x in devs), 1),
                            "limit_minutes": effective_limit(db, r, d),
                            "by_device": {x["device"]: round(x["minutes"], 1) for x in devs}})
        out.append({"child": r["name"], "days": per_day})
    return out


def device_status(db: DB, cfg: Config) -> list[dict]:
    out = []
    for d in db.all("SELECT * FROM devices ORDER BY id"):
        age = None if d["last_seen"] is None else now_ts() - d["last_seen"]
        out.append({"device": d["id"], "last_seen_seconds_ago": age, "agent_version": d["agent_version"],
                    "stale": age is None or age > cfg.stale_after_s})
    return out


# ---------------------------------------------------------------- agent devices + sync
def hash_key(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


def create_device(db: DB, device_id: str) -> str:
    if not re.match(r"^[A-Za-z0-9._-]{1,40}$", device_id):
        raise PolicyError("device id: letters, digits, . _ - only")
    key = secrets.token_urlsafe(32)
    db.execute("INSERT INTO devices(id, key_hash) VALUES (?,?) ON CONFLICT(id) DO UPDATE SET key_hash=excluded.key_hash",
               (device_id, hash_key(key)))
    audit(db, "admin-cli", "device_key_issued", {"device": device_id})
    return key


def authenticate_device(db: DB, device_id: str, key: str) -> bool:
    row = db.one("SELECT key_hash FROM devices WHERE id=?", (device_id,))
    # compare even when the device is unknown so timing doesn't reveal which ids exist
    expected = row["key_hash"] if row else hash_key("x" * 43)
    ok = hmac.compare_digest(expected, hash_key(key or ""))
    return bool(row) and ok


def agent_sync(db: DB, cfg: Config, device_id: str, payload: dict, ip: str = "") -> dict:
    day = str(payload.get("day", ""))
    if not DAY_RE.match(day):
        raise PolicyError("bad day")
    today, ts = day_key(cfg), now_ts()
    if abs((datetime.strptime(day, "%Y%m%d") - datetime.strptime(today, "%Y%m%d")).days) > 1:
        raise PolicyError("agent clock/timezone differs from server TIMEZONE by more than a day")
    known = {r["name"].lower(): r["name"] for r in db.all("SELECT name FROM children")}
    with db.tx():
        for u in (payload.get("users") or [])[:50]:
            n = known.get(str(u.get("name", "")).lower())
            m = u.get("minutes")
            if n is None or not isinstance(m, (int, float)) or m < 0 or m > 1440:
                continue
            db.execute("INSERT INTO usage(device, child, day, minutes, updated_at) VALUES (?,?,?,?,?) "
                       "ON CONFLICT(device, child, day) DO UPDATE SET minutes=excluded.minutes, updated_at=excluded.updated_at",
                       (device_id, n, day, float(m), ts))
        db.execute("UPDATE devices SET last_seen=?, agent_version=?, last_ip=? WHERE id=?",
                   (ts, str(payload.get("agent_version", ""))[:20], ip[:45], device_id))
    users = []
    for r in db.all("SELECT * FROM children ORDER BY name"):
        b = db.one("SELECT minutes FROM bonuses WHERE child=? AND day=?", (r["name"], day))
        users.append({"Name": r["name"], "Weekday": r["weekday"], "Weekend": r["weekend"],
                      "WeekdayHours": r["weekday_hours"] or "", "WeekendHours": r["weekend_hours"] or "",
                      "Bonus": b["minutes"] if b else 0, "LockedUntil": r["locked_until"]})
    # server_time + utc_offset let the agent compute the server's wall-clock time, so a child changing the PC's
    # clock or time zone doesn't shift the allowed-hours window.
    offset_min = int(local_dt(cfg, ts).utcoffset().total_seconds() // 60)
    return {"server_time": ts, "utc_offset_minutes": offset_min, "day": day, "Users": users}
