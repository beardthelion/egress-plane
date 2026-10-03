import base64

import requests


def send(blob):
    return requests.post(base64.b64decode(blob).decode())
