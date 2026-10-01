import requests


def probe(target):
    return requests.delete(target)
