import os
import time
import secrets
import hashlib
from typing import Optional, Dict, Tuple

import aiosqlite

LICENSE_PEPPER = os.environ.get("LICENSE_PEPPER", "")
if not LICENSE_PEPPER or len(LICENSE_PEPPER) < 32:
    raise SystemExit("Missing/weak LICENSE_PEPPER env var. Use 32+ chars random.")

PEPPER_BYTES = LICENSE_PEPPER.encode("utf-8")

DEFAULT_DB = os.path.join(os.path.dirname(__file__), "licenses.db")
DB_PATH = os.environ.get("LICENSE_DB_PATH", DEFAULT_DB)

# Ensure parent directory exists (Render disk path etc.)
_db_dir = os.path.dirname(DB_PATH)
if _db_dir and not os.path.exists(_db_dir):
    os.makedirs(_db_dir, exist_ok=True)

def now_ts() -> int:
    return int(time.time())

def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def normalize_key(k: str) -> str:
    return k.strip().upper()

def hash_license_key(license_key: str) -> str:
    return sha256_hex(PEPPER_BYTES + normalize_key(license_key).encode("utf-8"))

def hash_hwid(hwid: str) -> str:
    return sha256_hex(PEPPER_BYTES + hwid.strip().lower().encode("utf-8"))

def generate_license_key() -> str:
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    def group(n: int) -> str:
        return "".join(secrets.choice(alphabet) for _ in range(n))
    return "DBX-" + "-".join(group(5) for _ in range(5))

def fmt_ts(ts: Optional[int]) -> str:
    if ts is None:
        return "lifetime"
    return f"<t:{ts}:F> (<t:{ts}:R>)"

CREATE_LICENSES_SQL = """
CREATE TABLE IF NOT EXISTS licenses (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  license_hash  TEXT UNIQUE NOT NULL,
  created_at    INTEGER NOT NULL,
  created_by    INTEGER NOT NULL,
  expires_at    INTEGER,
  revoked       INTEGER NOT NULL DEFAULT 0,
  hwid_hash     TEXT,
  last_seen_at  INTEGER
);
CREATE INDEX IF NOT EXISTS idx_license_hash ON licenses(license_hash);
"""

async def db_init():
    print("DB_PATH:", DB_PATH)
    async with aiosqlite.connect(DB_PATH) as db:
        await db.executescript(CREATE_LICENSES_SQL)
        await db.commit()

async def db_create_license(expires_at: Optional[int], created_by: int) -> str:
    key = generate_license_key()
    lhash = hash_license_key(key)
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "INSERT INTO licenses(license_hash, created_at, created_by, expires_at, revoked) VALUES(?,?,?,?,0)",
            (lhash, now_ts(), created_by, expires_at)
        )
        await db.commit()
    return key

async def db_find_license_row(license_key: str):
    lhash = hash_license_key(license_key)
    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute(
            "SELECT id, created_at, created_by, expires_at, revoked, hwid_hash, last_seen_at "
            "FROM licenses WHERE license_hash=?",
            (lhash,)
        )
        return await cur.fetchone()

async def db_set_revoked(license_key: str, revoked: bool) -> bool:
    lhash = hash_license_key(license_key)
    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute("UPDATE licenses SET revoked=? WHERE license_hash=?",
                               (1 if revoked else 0, lhash))
        await db.commit()
        return cur.rowcount > 0

async def db_delete_license(license_key: str) -> bool:
    lhash = hash_license_key(license_key)
    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute("DELETE FROM licenses WHERE license_hash=?", (lhash,))
        await db.commit()
        return cur.rowcount > 0

async def db_add_time(license_key: str, add_seconds: int) -> Tuple[bool, str]:
    lhash = hash_license_key(license_key)
    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute("SELECT expires_at FROM licenses WHERE license_hash=?", (lhash,))
        row = await cur.fetchone()
        if not row:
            return False, "not_found"

        expires_at = row[0]
        if expires_at is None:
            return True, "lifetime_noop"

        base = max(int(expires_at), now_ts())
        new_exp = base + int(add_seconds)

        await db.execute("UPDATE licenses SET expires_at=? WHERE license_hash=?",
                         (new_exp, lhash))
        await db.commit()
        return True, str(new_exp)

async def db_reset_hwid(license_key: str) -> bool:
    lhash = hash_license_key(license_key)
    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute("UPDATE licenses SET hwid_hash=NULL WHERE license_hash=?", (lhash,))
        await db.commit()
        return cur.rowcount > 0

# API validate/bind HWID (shared by web API)
async def db_check_and_bind(license_key: str, hwid: str) -> Tuple[bool, str, Optional[int]]:
    license_key = normalize_key(license_key)
    hwid = hwid.strip().lower()
    if len(license_key) < 10 or len(license_key) > 128:
        return False, "invalid", None
    if len(hwid) < 16 or len(hwid) > 128:
        return False, "invalid", None

    lhash = hash_license_key(license_key)
    hh = hash_hwid(hwid)
    t = now_ts()

    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute(
            "SELECT id, expires_at, revoked, hwid_hash FROM licenses WHERE license_hash=?",
            (lhash,)
        )
        row = await cur.fetchone()
        if not row:
            return False, "invalid", None

        lic_id, expires_at, revoked, bound_hwid = row
        if revoked:
            return False, "invalid", None

        if expires_at is not None and int(expires_at) < t:
            return False, "expired", None

        if bound_hwid is None:
            await db.execute(
                "UPDATE licenses SET hwid_hash=?, last_seen_at=? WHERE id=?",
                (hh, t, lic_id)
            )
            await db.commit()
            return True, "ok", expires_at

        if str(bound_hwid) != str(hh):
            return False, "hwid_mismatch", None

        await db.execute("UPDATE licenses SET last_seen_at=? WHERE id=?", (t, lic_id))
        await db.commit()
        return True, "ok", expires_at
