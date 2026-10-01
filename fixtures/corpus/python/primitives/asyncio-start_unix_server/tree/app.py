import asyncio


def probe(target):
    return asyncio.start_unix_server(None, target)
