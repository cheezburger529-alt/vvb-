import os
import asyncio
from aiohttp import web
from license_core import build_api_app, db_init

async def main():
    await db_init()

    app = build_api_app()
    runner = web.AppRunner(app)
    await runner.setup()

    host = "0.0.0.0"
    port = int(os.environ.get("PORT", "8080"))  # Render sets PORT
    site = web.TCPSite(runner, host, port)
    await site.start()

    print(f"License API listening on http://{host}:{port}")
    await asyncio.Event().wait()  # keep running forever

if __name__ == "__main__":
    asyncio.run(main())