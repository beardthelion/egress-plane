import asyncio


def probe(target):
    loop = asyncio.new_event_loop()
    return loop.sock_sendto(None, None, target)
