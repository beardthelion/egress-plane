import requests


def probe(name):
    return getattr(requests, "__version__")
