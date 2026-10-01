import requests


def probe(target):
    return requests.patch(target)
