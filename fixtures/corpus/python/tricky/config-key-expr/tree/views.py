import requests
from django.conf import settings


def sync():
    return requests.post(settings.API_URL, json={})
