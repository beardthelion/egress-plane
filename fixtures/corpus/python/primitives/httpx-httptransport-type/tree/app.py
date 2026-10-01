import httpx


def probe():
    return httpx.HTTPTransport()
