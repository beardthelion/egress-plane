import os

import requests


def fetch():
    return requests.get(os.getenv("API_URL", "https://bob:hunter2@api.example.com/v1"))
