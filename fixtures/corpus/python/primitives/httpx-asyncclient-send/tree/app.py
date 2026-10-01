import httpx


def probe():
    s = httpx.AsyncClient()
    return s.send()
