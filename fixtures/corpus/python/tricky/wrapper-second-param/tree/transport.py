import requests


def call(method, url):
    return requests.request(method, url)


def ping():
    return call("GET", "https://api.example.com/ping")
