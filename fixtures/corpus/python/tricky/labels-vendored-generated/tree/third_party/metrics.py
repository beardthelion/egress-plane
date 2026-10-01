import urllib.request


def push():
    urllib.request.urlopen("https://metrics.example.com/push")
