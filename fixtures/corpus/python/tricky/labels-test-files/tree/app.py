import requests


def health():
    return requests.get("https://api.example.com/health")
