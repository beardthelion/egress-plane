import os

import requests


def post_json(url, body):
    return requests.post(url, json=body)


def send_hook():
    return post_json("https://hook.invalid", {"k": 1})


def send_env():
    return post_json(os.environ["HOOK"], {"k": 2})


def send_computed(name):
    return post_json(build_url(name), {"k": 3})


def build_url(name):
    return "https://" + name + ".invalid/x"
