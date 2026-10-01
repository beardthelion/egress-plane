import httpx


def probe(target):
    return httpx.post(target)
