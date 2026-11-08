"""SQLite storage. One connection, guarded by a lock - fine for a household-sized service."""
import os
import sqlite3
import threading

SCHEMA = """
CREATE TABLE IF NOT EXISTS children (
    name TEXT PRIMARY KEY COLLATE NOCASE,
    weekday INTEGER NOT NULL,
    weekend INTEGER NOT NULL,
    weekday_hours TEXT,
    weekend_hours TEXT,
    locked_until INTEGER NOT NULL DEFAULT 0,
    updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS bonuses (
    child TEXT NOT NULL COLLATE NOCASE,
    day TEXT NOT NULL,
    minutes INTEGER NOT NULL,
    PRIMARY KEY (child, day)
);
CREATE TABLE IF NOT EXISTS usage (
    device TEXT NOT NULL,
    child TEXT NOT NULL COLLATE NOCASE,
    day TEXT NOT NULL,
    minutes REAL NOT NULL,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (device, child, day)
);
CREATE TABLE IF NOT EXISTS devices (
    id TEXT PRIMARY KEY,
    key_hash TEXT NOT NULL,
    last_seen INTEGER,
    agent_version TEXT,
    last_ip TEXT
);
CREATE TABLE IF NOT EXISTS parents (
    name TEXT PRIMARY KEY COLLATE NOCASE,
    pw_hash TEXT NOT NULL,
    totp_secret TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts INTEGER NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    details TEXT
);
CREATE TABLE IF NOT EXISTS oauth_clients (client_id TEXT PRIMARY KEY, created_at INTEGER NOT NULL, json TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS oauth_pending (req_id TEXT PRIMARY KEY, expires_at INTEGER NOT NULL, json TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS oauth_codes (hash TEXT PRIMARY KEY, expires_at INTEGER NOT NULL, json TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS oauth_tokens (
    hash TEXT PRIMARY KEY,
    kind TEXT NOT NULL,            -- 'access' | 'refresh'
    pair_id TEXT NOT NULL,         -- links an access token to its refresh token
    expires_at INTEGER,
    json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS oauth_tokens_pair ON oauth_tokens(pair_id);
"""


class DB:
    def __init__(self, path: str):
        if path != ":memory:":
            os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        self._lock = threading.RLock()
        self._c = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self._c.row_factory = sqlite3.Row
        self._c.execute("PRAGMA journal_mode=WAL")
        self._c.execute("PRAGMA foreign_keys=ON")
        self._c.executescript(SCHEMA)

    def execute(self, sql: str, params: tuple = ()):
        with self._lock:
            return self._c.execute(sql, params)

    def all(self, sql: str, params: tuple = ()) -> list[sqlite3.Row]:
        with self._lock:
            return self._c.execute(sql, params).fetchall()

    def one(self, sql: str, params: tuple = ()):
        with self._lock:
            return self._c.execute(sql, params).fetchone()

    def tx(self):
        """Context manager for an atomic multi-statement change."""
        db = self

        class _Tx:
            def __enter__(self_inner):
                db._lock.acquire()
                db._c.execute("BEGIN IMMEDIATE")
                return db

            def __exit__(self_inner, exc_type, exc, tb):
                try:
                    db._c.execute("ROLLBACK" if exc_type else "COMMIT")
                finally:
                    db._lock.release()
                return False

        return _Tx()
