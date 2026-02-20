import os
import time
import hashlib
import secrets
from typing import Optional, Dict, Tuple
from aiohttp import web
import aiosqlite

# =========================
# CONFIG
# =========================
LICENSE_PEPPER = os.environ.get("LICENSE_PEPPER", "")
if not LICENSE_PEPPER or len(LICENSE_PEPPER) < 32:
    raise SystemExit("Missing/weak LICENSE_PEPPER env var. Use 32+ chars random.")

PEPPER_BYTES = LICENSE_PEPPER.encode("utf-8")

# IMPORTANT: for Render persistent disk mount use /var/data
DB_PATH = os.environ.get("LICENSE_DB_PATH", "/var/data/licenses.db")

# =========================
# DB SCHEMA
# =========================
CREATE_LICENSES_SQL = """
CREATE TABLE IF NOT EXISTS licenses (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  license_hash  TEXT UNIQUE NOT NULL,
  created_at    INTEGER NOT NULL,
  created_by    INTEGER NOT NULL,
  expires_at    INTEGER, -- NULL = lifetime
  revoked       INTEGER NOT NULL DEFAULT 0,
  hwid_hash     TEXT,    -- NULL until first activation
  last_seen_at  INTEGER
);
CREATE INDEX IF NOT EXISTS idx_license_hash ON licenses(license_hash);
"""

# =========================
# HELPERS
# =========================
def now_ts() -> int:
    return int(time.time())

def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def normalize_key(k: str) -> str:
    return k.strip().upper()

def hash_license_key(license_key: str) -> str:
    return sha256_hex(PEPPER_BYTES + license_key.strip().encode("utf-8"))

def hash_hwid(hwid: str) -> str:
    return sha256_hex(PEPPER_BYTES + hwid.strip().encode("utf-8"))

def generate_license_key() -> str:
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    def group(n: int) -> str:
        return "".join(secrets.choice(alphabet) for _ in range(n))
    return "DBX-" + "-".join(group(5) for _ in range(5))

# =========================
# DB OPS
# =========================
async def db_init():
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

        await db.execute("UPDATE licenses SET expires_at=? WHERE license_hash=?", (new_exp, lhash))
        await db.commit()
        return True, str(new_exp)

async def db_reset_hwid(license_key: str) -> bool:
    lhash = hash_license_key(license_key)
    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute("UPDATE licenses SET hwid_hash=NULL WHERE license_hash=?", (lhash,))
        await db.commit()
        return cur.rowcount > 0

# =========================
# LICENSE API (aiohttp)
# =========================
RATE_LIMIT_WINDOW = 60
RATE_LIMIT_MAX = 60
_rate: Dict[str, Tuple[int, int]] = {}

def rate_limit_ok(ip: str) -> bool:
    t = now_ts()
    count, reset = _rate.get(ip, (0, t + RATE_LIMIT_WINDOW))
    if t > reset:
        _rate[ip] = (1, t + RATE_LIMIT_WINDOW)
        return True
    if count >= RATE_LIMIT_MAX:
        _rate[ip] = (count, reset)
        return False
    _rate[ip] = (count + 1, reset)
    return True

async def api_health(_: web.Request):
    return web.json_response({"ok": True})

async def api_activate(request: web.Request):
    ip = request.remote or "unknown"
    if not rate_limit_ok(ip):
        return web.json_response({"ok": False, "message": "rate_limited"}, status=429)

    try:
        data = await request.json()
    except Exception:
        return web.json_response({"ok": False, "message": "bad_json"}, status=400)

    license_key = normalize_key(str(data.get("license_key", "")))
    hwid = str(data.get("hwid", "")).strip().lower()

    if len(license_key) < 10 or len(license_key) > 128:
        return web.json_response({"ok": False, "message": "invalid"}, status=401)
    if len(hwid) < 16 or len(hwid) > 128:
        return web.json_response({"ok": False, "message": "invalid"}, status=401)

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
            return web.json_response({"ok": False, "message": "invalid"}, status=401)

        lic_id, expires_at, revoked, bound_hwid = row
        if revoked:
            return web.json_response({"ok": False, "message": "invalid"}, status=401)

        if expires_at is not None and int(expires_at) < t:
            return web.json_response({"ok": False, "message": "expired"}, status=401)

        if bound_hwid is None:
            await db.execute(
                "UPDATE licenses SET hwid_hash=?, last_seen_at=? WHERE id=?",
                (hh, t, lic_id)
            )
            await db.commit()
            return web.json_response({"ok": True, "expires_at": expires_at, "bound": True})

        if str(bound_hwid) != str(hh):
            return web.json_response({"ok": False, "message": "hwid_mismatch"}, status=401)

        await db.execute("UPDATE licenses SET last_seen_at=? WHERE id=?", (t, lic_id))
        await db.commit()
        return web.json_response({"ok": True, "expires_at": expires_at, "bound": True})

def build_api_app() -> web.Application:
    app = web.Application()
    app.router.add_get("/health", api_health)
    app.router.add_post("/v1/activate", api_activate)
    return app