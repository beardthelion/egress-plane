import requests


def probe(target):
    return requests.put(target)
