import asyncio


def probe(target):
    return asyncio.open_unix_connection(target)
