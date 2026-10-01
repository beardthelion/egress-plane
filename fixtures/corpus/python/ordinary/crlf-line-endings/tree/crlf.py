import requests


def ping():
    return requests.head("https://api.example.com/ping")
