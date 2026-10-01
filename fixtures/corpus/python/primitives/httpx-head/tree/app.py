import httpx


def probe(target):
    return httpx.head(target)
