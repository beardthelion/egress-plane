import asyncio


def probe():
    return asyncio.get_running_loop()
