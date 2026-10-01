import requests


def ping():
    return requests.get("https://api.example.com/ping")
