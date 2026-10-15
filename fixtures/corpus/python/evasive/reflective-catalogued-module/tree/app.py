import requests


def probe(name):
    return getattr(requests, name)
