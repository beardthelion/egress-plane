import requests


def fetch_repo():
    return requests.get("https://h.example/x/ghp_abc123")


def fetch_offer():
    return requests.get("https://h.example/offers/risk-free")
