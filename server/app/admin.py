"""Admin CLI (run on the server, e.g. inside the container):

  python -m app.admin add-parent <name>      # prompts for a password, prints the authenticator secret
  python -m app.admin add-device <id>        # prints the device key ONCE (put it in the PC installer)
  python -m app.admin list
"""
import getpass
import os
import sys

from . import auth, core
from .db import DB


def main(argv: list[str]) -> int:
    db = DB(os.environ.get("DB_PATH", "./data/screentime.db"))
    cmd = argv[1] if len(argv) > 1 else ""
    if cmd == "add-parent" and len(argv) == 3:
        pw = getpass.getpass("Password (min 12 chars): ")
        if pw != getpass.getpass("Repeat: "):
            print("Passwords differ."); return 1
        secret, uri = auth.add_parent(db, argv[2], pw)
        print(f"\nParent '{argv[2]}' saved.\nAdd to your authenticator app (manual entry):\n  secret: {secret}\n  or URI: {uri}")
        core.audit(db, "admin-cli", "parent_saved", {"parent": argv[2]})
        return 0
    if cmd == "add-device" and len(argv) == 3:
        key = core.create_device(db, argv[2])
        print(f"\nDevice '{argv[2]}' key (shown once):\n  {key}")
        return 0
    if cmd == "list":
        for p in db.all("SELECT name FROM parents"): print("parent:", p["name"])
        for d in core.device_status(db, core.Config()): print("device:", d)
        for c in core.list_children(db, core.Config()): print("child:", c)
        return 0
    print(__doc__); return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
