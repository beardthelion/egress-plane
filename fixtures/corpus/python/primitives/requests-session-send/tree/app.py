import requests


def probe():
    s = requests.Session()
    return s.send()
