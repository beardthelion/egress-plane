import asyncio


def probe(target):
    loop = asyncio.get_running_loop()
    return loop.getaddrinfo(target)
