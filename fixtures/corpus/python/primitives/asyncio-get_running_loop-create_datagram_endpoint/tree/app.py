import asyncio


def probe(target):
    loop = asyncio.get_running_loop()
    return loop.create_datagram_endpoint(None, None, target)
