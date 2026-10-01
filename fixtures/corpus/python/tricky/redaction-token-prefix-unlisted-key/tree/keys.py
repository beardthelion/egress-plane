import requests


def lookup():
    return requests.get("https://api.example.com/lookup?id=AKIAFAKEFAKEFAKE1234&page=1")
