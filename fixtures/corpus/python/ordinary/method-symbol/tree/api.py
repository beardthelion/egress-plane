import requests


class Api:
    def fetch(self):
        return requests.get("https://api.example.com/me")
