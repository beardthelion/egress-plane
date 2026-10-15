import requests


def a(url):
    return b(url)


def b(url, seen=False):
    if seen:
        return requests.post(url)
    return a(url)


def outside():
    return a("https://x.invalid")
