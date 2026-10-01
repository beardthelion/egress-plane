import requests


def probe(target):
    return requests.options(target)
