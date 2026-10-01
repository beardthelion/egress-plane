import httpx


def probe(target):
    return httpx.stream(None, target)
