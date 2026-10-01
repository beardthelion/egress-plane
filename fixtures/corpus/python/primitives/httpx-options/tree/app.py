import httpx


def probe(target):
    return httpx.options(target)
