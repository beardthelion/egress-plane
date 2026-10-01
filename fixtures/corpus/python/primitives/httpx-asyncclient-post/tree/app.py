import httpx


def probe(target):
    s = httpx.AsyncClient()
    return s.post(target)
