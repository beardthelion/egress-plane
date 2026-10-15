import requests


def post_json(url, body):
    return requests.post(url, json=body)
