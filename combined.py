import asyncio
from api_server import start_api
from bot_worker import start_bot

async def main():
    await asyncio.gather(
        start_api(),
        start_bot()
    )

if __name__ == "__main__":
    asyncio.run(main())
