import asyncio


def probe(target):
    loop = asyncio.new_event_loop()
    return loop.create_datagram_endpoint(None, None, target)
