import requests


def outer():
    def inner():
        return requests.get("https://api.example.com/jobs")

    return inner()
