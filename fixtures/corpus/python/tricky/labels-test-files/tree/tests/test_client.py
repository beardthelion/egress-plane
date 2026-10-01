import requests


def test_health():
    assert requests.get("https://staging.example.com/health").ok
