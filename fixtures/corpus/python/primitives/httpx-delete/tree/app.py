import httpx


def probe(target):
    return httpx.delete(target)
