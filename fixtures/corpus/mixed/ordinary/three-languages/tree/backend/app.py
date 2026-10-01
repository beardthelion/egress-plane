import requests


def sync():
    return requests.post("https://api.example.com/sync")
