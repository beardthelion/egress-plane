import httpx


def probe():
    s = httpx.Client()
    return s.send()
