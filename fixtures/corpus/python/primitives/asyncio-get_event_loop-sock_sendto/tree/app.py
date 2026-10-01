import asyncio


def probe(target):
    loop = asyncio.get_event_loop()
    return loop.sock_sendto(None, None, target)
