import functools

import requests


def post_json(url, body):
    return requests.post(url, json=body)


def make(url):
    return functools.partial(post_json, url)


def register(cb):
    return cb("https://x.invalid", {})
