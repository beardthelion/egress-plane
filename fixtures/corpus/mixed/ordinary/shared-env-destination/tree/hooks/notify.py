import os

import requests
import yaml


def notify(payload):
    return requests.post(os.environ["WEBHOOK_URL"], data=yaml.safe_dump(payload))
