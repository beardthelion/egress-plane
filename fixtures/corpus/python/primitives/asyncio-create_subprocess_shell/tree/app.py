import asyncio


def probe(target):
    return asyncio.create_subprocess_shell(target)
