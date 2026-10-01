import asyncio


def probe(target):
    loop = asyncio.get_running_loop()
    return loop.create_unix_server(None, target)
