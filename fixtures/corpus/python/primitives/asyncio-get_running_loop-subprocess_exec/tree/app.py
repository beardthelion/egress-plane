import asyncio


def probe(target):
    loop = asyncio.get_running_loop()
    return loop.subprocess_exec(None, target)
