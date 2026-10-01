import httpx


def probe(target):
    s = httpx.AsyncClient()
    return s.request(None, target)
