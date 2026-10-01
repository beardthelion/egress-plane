import requests


def test_ping():
    requests.get("https://staging.example.com/ping")
