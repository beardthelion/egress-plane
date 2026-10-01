import requests


def probe(target):
    s = requests.Session()
    return s.request(None, target)
