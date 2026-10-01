import httpx


def probe(target):
    return httpx.put(target)
