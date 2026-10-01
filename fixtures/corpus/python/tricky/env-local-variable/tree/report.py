import os

import requests


def report(data):
    url = os.environ["REPORT_URL"]
    requests.post(url, json=data)
