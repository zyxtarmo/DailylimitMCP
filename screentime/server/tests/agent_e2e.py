"""Runs the REAL DailyLimit.ps1 (under pwsh on Linux, with a fake Wts session API) against the REAL server.
Usage: python tests/agent_e2e.py /path/to/pwsh /path/to/DailyLimit.ps1"""
import json
import os
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone

import httpx

PWSH, SCRIPT = sys.argv[1], os.path.abspath(sys.argv[2])
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
PORT = 8766
BASE = f"http://localhost:{PORT}"
tmp = tempfile.mkdtemp()
PD = os.path.join(tmp, "ProgramData")
DL = os.path.join(PD, "DailyLimit")
os.makedirs(DL)
env = {**os.environ, "DB_PATH": os.path.join(tmp, "s.db"), "BASE_URL": BASE, "TIMEZONE": "UTC", "MAX_BONUS_PER_DAY": "60"}
os.environ.update(env)
from app import core  # noqa: E402
from app.db import DB  # noqa: E402

db, cfg = DB(env["DB_PATH"]), core.Config()
key = core.create_device(db, "pc-test")
json.dump({"Url": BASE, "DeviceId": "pc-test", "Key": key}, open(os.path.join(DL, "server.json"), "w"))

HARNESS = os.path.join(tmp, "harness.ps1")
open(HARNESS, "w").write(r'''
Add-Type -TypeDefinition @"
using System; using System.Collections.Generic; using System.IO;
public static class Wts {
  public static List<string> Sessions() { var l = new List<string>();
    foreach (var s in (Environment.GetEnvironmentVariable("FAKE_SESSIONS") ?? "").Split(new[]{';'}, StringSplitOptions.RemoveEmptyEntries)) l.Add(s); return l; }
  public static void Logoff(int id) { File.AppendAllText(Environment.GetEnvironmentVariable("FAKE_WTS_LOG"), "logoff:" + id + "\n"); }
  public static void Msg(int id, string t, string x) { File.AppendAllText(Environment.GetEnvironmentVariable("FAKE_WTS_LOG"), "msg:" + id + ":" + x + "\n"); }
}
"@
Invoke-Expression ("& '" + $env:FAKE_SCRIPT + "' " + $env:FAKE_ARGS)
''')
WTSLOG = os.path.join(tmp, "wts.log")
ok = True


def check(label, cond, extra=""):
    global ok
    print(("PASS " if cond else "FAIL ") + label, "" if cond else f"\n     {extra}")
    ok &= bool(cond)


def run(sessions="", args="", rewind=True):
    """One agent tick. rewind=True pretends the previous tick was exactly 60 s ago."""
    sf = os.path.join(DL, "state", "kid1.json")
    if rewind and os.path.exists(sf):
        s = json.load(open(sf))
        s["LastTicks"] = int((datetime.now(timezone.utc).replace(tzinfo=None) - datetime(1, 1, 1)).total_seconds() * 1e7) - 600000000
        json.dump(s, open(sf, "w"))
    if os.path.exists(WTSLOG):
        os.remove(WTSLOG)
    e = {**env, "ProgramData": PD, "FAKE_SESSIONS": sessions, "FAKE_WTS_LOG": WTSLOG, "FAKE_SCRIPT": SCRIPT, "FAKE_ARGS": args}
    p = subprocess.run([PWSH, "-NoProfile", "-File", HARNESS], env=e, capture_output=True, text=True, timeout=120)
    calls = open(WTSLOG).read().splitlines() if os.path.exists(WTSLOG) else []
    if p.returncode or p.stderr.strip():
        print("   pwsh stderr/rc:", p.returncode, p.stderr.strip()[:600])
    return calls, p.stdout


def state():
    return json.load(open(os.path.join(DL, "state", "kid1.json")))


def log():
    f = os.path.join(DL, "log.txt")
    return open(f).read() if os.path.exists(f) else ""


server = subprocess.Popen([sys.executable, "-m", "uvicorn", "app.main:app", "--port", str(PORT), "--log-level", "warning"], cwd=ROOT, env=env)
try:
    for _ in range(50):
        try:
            if httpx.get(BASE + "/healthz").status_code == 200:
                break
        except Exception:
            time.sleep(0.2)
    KID = "1|kid1|0;2|someone-else|0"        # session 1 = kid1 (Active), 2 = unmanaged user

    calls, out = run("", rewind=False)
    check("S1 first sync with no children works", os.path.exists(os.path.join(DL, "policy.json")), out)
    pol = json.load(open(os.path.join(DL, "policy.json")))
    check("S1 policy has trusted-clock fields", "ClockOffsetSeconds" in pol and pol["UtcOffsetMinutes"] == 0 and abs(pol["ClockOffsetSeconds"]) < 5, pol)

    core.set_schedule(db, cfg, "t", "kid1", weekday_minutes=3, weekend_minutes=3)
    calls, _ = run(KID, rewind=False)                       # picks up the new child via sync; counts 1 min
    check("S2 child policy downloaded + minute counted", abs(state()["Minutes"] - 1.0) < 0.2, state())
    check("S2 warned at 2 minutes left, only for kid1", any(c.startswith("msg:1:") and "2 minute" in c for c in calls) and not any(c.startswith("msg:2:") or c == "logoff:2" for c in calls), calls)

    calls, _ = run(KID)
    check("S3 second minute -> 1 minute warning", any(c.startswith("msg:1:") and "1 minute" in c for c in calls), calls)
    usage = core.get_usage(db, cfg, "kid1", 1)[0]["days"][0]["used_minutes"]
    check("S3 usage uploaded to server (previous tick's count)", abs(usage - 1.0) < 0.3 or abs(usage - 2.0) < 0.3, usage)

    calls, _ = run(KID)
    check("S4 limit reached -> message + logoff of session 1 only", "logoff:1" in calls and "logoff:2" not in calls and any("daily time used up" in c for c in calls), calls)

    core.add_bonus(db, cfg, "t", "kid1", 10, "homework", confirm=True)
    calls, _ = run(KID)
    check("S5 bonus from server lets them stay (no logoff)", "logoff:1" not in calls, (calls, state()))
    w = state()["Warned"]
    check("S5 warnings re-armed after bonus: 5 and 1 can fire again, 10 stays done", w in ([10], 10), w)
    _, out = run("", "-Status", rewind=False)
    check("S5 -Status shows managed mode + limit incl. bonus", "Managed by server" in out and "/ 13 min" in out, out)

    core.lock(db, "t", "kid1", 30, "dinner")
    before = state()["Minutes"]
    calls, _ = run(KID)
    check("S6 parent lock -> logoff, reason shown", "logoff:1" in calls and any("locked by a parent" in c for c in calls), calls)
    check("S6 locked time is not counted", abs(state()["Minutes"] - before) < 0.01, (before, state()))

    core.unlock(db, "t", "kid1", confirm=True)
    calls, _ = run(KID)
    check("S7 unlock -> allowed again", "logoff:1" not in calls, calls)

    h = datetime.now(timezone.utc).hour
    win = f"{h + 2:02d}:00-{h + 3:02d}:00" if h < 20 else "01:00-02:00"
    core.set_schedule(db, cfg, "t", "kid1", weekday_hours=win, weekend_hours=win)
    calls, _ = run(KID)
    check("S8 outside allowed hours -> logoff", "logoff:1" in calls and any("outside allowed hours" in c for c in calls), (win, calls))

    server.terminate(); server.wait(timeout=10)
    calls, out = run(KID)
    check("S9 server down: cached policy still enforced", "logoff:1" in calls, calls)
    check("S9 sync failure logged once", log().count("server sync failed") == 1, log())
    run(KID)
    check("S9 repeated failure not spammed", log().count("server sync failed") == 1, log())

    pf = os.path.join(DL, "policy.json")
    p = json.load(open(pf)); p["ClockOffsetSeconds"] = 2 * 3600 + 1800
    json.dump(p, open(pf, "w"))
    calls, _ = run(KID, "-NoSync")
    check("S10 trusted clock offset applied (shifted into window -> allowed)", "logoff:1" not in calls, calls)
finally:
    if server.poll() is None:
        server.terminate()
print("\nALL PASSED" if ok else "\nSOME FAILED")
sys.exit(0 if ok else 1)
