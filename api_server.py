import os
import asyncio
from aiohttp import web

from license_core import db_init, db_check_and_bind

async def api_health(_: web.Request):
    return web.json_response({"ok": True})

async def api_activate(request: web.Request):
    try:
        data = await request.json()
    except Exception:
        return web.json_response({"ok": False, "message": "bad_json"}, status=400)

    license_key = str(data.get("license_key", "")).strip()
    hwid = str(data.get("hwid", "")).strip()

    ok, msg, expires_at = await db_check_and_bind(license_key, hwid)
    if not ok:
        status = 401
        return web.json_response({"ok": False, "message": msg}, status=status)

    return web.json_response({"ok": True, "expires_at": expires_at})

def build_api_app() -> web.Application:
    app = web.Application()
    app.router.add_get("/health", api_health)
    app.router.add_post("/v1/activate", api_activate)
    return app

async def start_api():
    await db_init()
    host = "0.0.0.0"
    port = int(os.environ.get("PORT", "8080"))  # Render uses PORT
    app = build_api_app()
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, host, port)
    await site.start()
    print(f"API listening on http://{host}:{port}")

    # Keep alive forever
    while True:
        await asyncio.sleep(3600)

if __name__ == "__main__":
    asyncio.run(start_api())
