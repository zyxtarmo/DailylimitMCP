import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from app import core  # noqa: E402
from app.db import DB  # noqa: E402

A = "tester"


@pytest.fixture
def env():
    return DB(":memory:"), core.Config()


def mk(env, **kw):
    db, cfg = env
    core.set_schedule(db, cfg, A, "kid1", weekday_minutes=90, weekend_minutes=150,
                      weekday_hours="15:00-20:00", weekend_hours="09:00-21:00", **kw)
    return db, cfg


def test_create_and_defaults(env):
    db, cfg = env
    r = core.set_schedule(db, cfg, A, "kid2")
    assert r["created"] and r["weekday"] == cfg.default_weekday and r["weekday_hours"] is None


def test_loosening_requires_confirm_and_tightening_does_not(env):
    db, cfg = mk(env)
    for kw in ({"weekday_minutes": 120}, {"weekend_hours": "08:00-21:00"}, {"weekday_hours": "15:00-21:00"}, {"weekday_hours": "none"}):
        with pytest.raises(core.NeedsConfirmation):
            core.set_schedule(db, cfg, A, "kid1", **kw)
    # tightening is free
    core.set_schedule(db, cfg, A, "kid1", weekday_minutes=60, weekday_hours="16:00-19:00")
    row = core.get_child(db, "kid1")
    assert row["weekday"] == 60 and row["weekday_hours"] == "16:00-19:00"
    # adding a restriction where there was none is tightening
    core.set_schedule(db, cfg, A, "kid2")
    core.set_schedule(db, cfg, A, "kid2", weekday_hours="10:00-18:00")
    # with confirm, loosening is applied and audited
    core.set_schedule(db, cfg, A, "kid1", weekday_minutes=200, confirm=True)
    assert core.get_child(db, "kid1")["weekday"] == 200
    assert any(e["action"] == "schedule_set" and e["details"]["loosened"] for e in core.recent_audit(db))


def test_hours_validation(env):
    db, cfg = env
    for bad in ("8-20", "20:00-08:00", "25:00-26:00", "10:00-10:00", "10:60-12:00", "10:00-24:30"):
        with pytest.raises(core.PolicyError):
            core.set_schedule(db, cfg, A, "kid3", weekday_hours=bad)
    assert core.set_schedule(db, cfg, A, "kid3", weekday_hours="09:00-24:00")["weekday_hours"] == "09:00-24:00"
    for bad in ("..\\x", "a/b", "", "x" * 40):
        with pytest.raises(core.PolicyError):
            core.check_name(bad)


def test_bonus_rules(env):
    db, cfg = mk(env)
    with pytest.raises(core.PolicyError):                       # reason required
        core.add_bonus(db, cfg, A, "kid1", 15, "", confirm=True)
    with pytest.raises(core.NeedsConfirmation):
        core.add_bonus(db, cfg, A, "kid1", 15, "homework", confirm=False)
    assert core.add_bonus(db, cfg, A, "kid1", 15, "homework", confirm=True)["bonus_today"] == 15
    assert core.add_bonus(db, cfg, A, "kid1", 40, "movie", confirm=True)["bonus_today"] == 55
    with pytest.raises(core.PolicyError) as e:                  # cap 60/day
        core.add_bonus(db, cfg, A, "kid1", 10, "more", confirm=True)
    assert "cap" in str(e.value)
    assert core.add_bonus(db, cfg, A, "kid1", -30, "")["bonus_today"] == 25     # reducing needs no confirm
    r = core.add_bonus(db, cfg, A, "kid1", -1000, "")           # floors at -base, limit never negative
    assert r["limit_today"] == 0


def test_lock_only_extends_and_unlock_needs_confirm(env):
    db, cfg = mk(env)
    a = core.lock(db, A, "kid1", 60)["locked_until"]
    b = core.lock(db, A, "kid1", 5)["locked_until"]             # shorter lock must not shorten
    assert a == b
    assert core.list_children(db, cfg)[0]["locked_until"]
    with pytest.raises(core.NeedsConfirmation):
        core.unlock(db, A, "kid1")
    core.unlock(db, A, "kid1", confirm=True)
    assert core.list_children(db, cfg)[0]["locked_until"] is None


def test_remove_child_needs_confirm(env):
    db, cfg = mk(env)
    with pytest.raises(core.NeedsConfirmation):
        core.remove_child(db, A, "kid1", False)
    core.remove_child(db, A, "kid1", True)
    with pytest.raises(core.PolicyError):
        core.get_child(db, "kid1")


def test_device_auth_and_sync(env):
    db, cfg = mk(env)
    key = core.create_device(db, "pc1")
    assert core.authenticate_device(db, "pc1", key)
    assert not core.authenticate_device(db, "pc1", key + "x")
    assert not core.authenticate_device(db, "nope", key)
    day = core.day_key(cfg)
    core.add_bonus(db, cfg, A, "kid1", 20, "test", confirm=True)
    out = core.agent_sync(db, cfg, "pc1", {"day": day, "agent_version": "2",
                                           "users": [{"name": "KID1", "minutes": 12.5}, {"name": "ghost", "minutes": 5},
                                                     {"name": "kid1x", "minutes": -4}]})
    u = {x["Name"]: x for x in out["Users"]}
    assert u["kid1"]["Bonus"] == 20 and u["kid1"]["WeekdayHours"] == "15:00-20:00"
    assert core.get_usage(db, cfg, "kid1", 1)[0]["days"][0]["used_minutes"] == 12.5
    assert core.get_usage(db, cfg, None, 1)[0]["child"] == "kid1" and len(core.get_usage(db, cfg)) == 1   # ghost ignored
    st = core.device_status(db, cfg)[0]
    assert st["device"] == "pc1" and not st["stale"] and st["agent_version"] == "2"
    with pytest.raises(core.PolicyError):
        core.agent_sync(db, cfg, "pc1", {"day": "20200101", "users": []})      # clock far off
    with pytest.raises(core.PolicyError):
        core.agent_sync(db, cfg, "pc1", {"day": "bad", "users": []})
    # lock shows up in policy
    core.lock(db, A, "kid1", 30)
    out = core.agent_sync(db, cfg, "pc1", {"day": day, "users": []})
    assert out["Users"][0]["LockedUntil"] > out["server_time"]
