import asyncio


def probe(target):
    loop = asyncio.get_event_loop()
    return loop.create_datagram_endpoint(None, None, target)
