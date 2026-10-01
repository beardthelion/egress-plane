import urllib.request


def read_feed():
    with urllib.request.urlopen("https://api.example.com/feed.xml") as resp:
        return resp.read()
