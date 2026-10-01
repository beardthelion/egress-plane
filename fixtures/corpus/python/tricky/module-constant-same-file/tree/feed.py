from urllib.request import urlopen

API = "https://api.example.com/v2"


def load():
    return urlopen(API).read()
