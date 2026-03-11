import sqlite3
import json
from config import Config

def get_db():
    conn = sqlite3.connect(Config.DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()

    c.executescript("""
        CREATE TABLE IF NOT EXISTS scans (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            name        TEXT,
            target      TEXT NOT NULL,
            scan_type   TEXT DEFAULT 'full',
            status      TEXT DEFAULT 'pending',
            progress    INTEGER DEFAULT 0,
            start_time  DATETIME DEFAULT CURRENT_TIMESTAMP,
            end_time    DATETIME,
            options     TEXT,
            error       TEXT
        );

        CREATE TABLE IF NOT EXISTS hosts (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id     INTEGER NOT NULL,
            ip          TEXT NOT NULL,
            mac         TEXT,
            hostname    TEXT,
            vendor      TEXT,
            device_type TEXT,
            os_info     TEXT,
            status      TEXT DEFAULT 'up',
            FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS ports (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            host_id     INTEGER NOT NULL,
            port        INTEGER NOT NULL,
            protocol    TEXT DEFAULT 'tcp',
            state       TEXT DEFAULT 'open',
            service     TEXT,
            version     TEXT,
            FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS baselines (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            name        TEXT NOT NULL,
            description TEXT,
            scan_id     INTEGER NOT NULL,
            created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (scan_id) REFERENCES scans(id)
        );

        CREATE TABLE IF NOT EXISTS alerts (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            severity    TEXT DEFAULT 'info',
            title       TEXT NOT NULL,
            message     TEXT,
            ip          TEXT,
            port        INTEGER,
            scan_id     INTEGER,
            is_read     INTEGER DEFAULT 0,
            tags        TEXT,
            created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS monitored_devices (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            ip          TEXT NOT NULL UNIQUE,
            name        TEXT,
            vendor      TEXT,
            model       TEXT,
            created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
        );
    """)
    conn.commit()
    conn.close()

def row_to_dict(row):
    if row is None:
        return None
    return dict(row)

def rows_to_list(rows):
    return [dict(r) for r in rows]
