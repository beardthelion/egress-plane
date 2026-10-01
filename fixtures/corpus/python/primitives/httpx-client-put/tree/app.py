import httpx


def probe(target):
    s = httpx.Client()
    return s.put(target)
