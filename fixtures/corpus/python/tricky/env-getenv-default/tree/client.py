import os

import requests


def fetch():
    return requests.get(os.getenv("API_URL", "https://api.example.com"))
