import os

import requests


def notify(payload):
    requests.post(os.environ["WEBHOOK_URL"], json=payload)
