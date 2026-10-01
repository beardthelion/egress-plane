import requests


def live_server():
    return requests.get("https://staging.example.com/ready")
