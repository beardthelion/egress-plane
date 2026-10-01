import asyncio


def probe(target):
    loop = asyncio.get_running_loop()
    return loop.sock_sendto(None, None, target)
