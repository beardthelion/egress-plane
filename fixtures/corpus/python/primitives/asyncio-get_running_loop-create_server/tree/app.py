import asyncio


def probe(target):
    loop = asyncio.get_running_loop()
    return loop.create_server(None, target)
