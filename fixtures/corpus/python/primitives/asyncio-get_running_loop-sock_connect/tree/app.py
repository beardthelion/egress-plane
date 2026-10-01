import asyncio


def probe(target):
    loop = asyncio.get_running_loop()
    return loop.sock_connect(None, target)
