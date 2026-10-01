import requests

from config import BASE_URL, TIMEOUT


def status():
    return requests.get(BASE_URL, timeout=TIMEOUT)
