import os

import requests


def users():
    base = os.environ["API_BASE"]
    return requests.get(f"{base}/v1/users")
