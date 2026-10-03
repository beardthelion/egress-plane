import requests


def fetch_page():
    return requests.get("https://bob:hunter2@api.example.com/x?token=abc&page=2")
