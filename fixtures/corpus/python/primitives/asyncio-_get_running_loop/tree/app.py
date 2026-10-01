import asyncio


def probe():
    return asyncio._get_running_loop()
