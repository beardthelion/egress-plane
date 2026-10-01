import asyncio


def probe(target):
    loop = asyncio.new_event_loop()
    return loop.subprocess_exec(None, target)
