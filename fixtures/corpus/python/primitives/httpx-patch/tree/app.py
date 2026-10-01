import httpx


def probe(target):
    return httpx.patch(target)
