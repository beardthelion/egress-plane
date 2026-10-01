import urllib.request


def check():
    return urllib.request.urlopen("https://api.example.com/version")
