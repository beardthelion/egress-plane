import httpx


def probe(target):
    return httpx.request(None, target)
