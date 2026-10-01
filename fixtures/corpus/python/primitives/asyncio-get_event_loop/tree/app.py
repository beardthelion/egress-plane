import asyncio


def probe():
    return asyncio.get_event_loop()
