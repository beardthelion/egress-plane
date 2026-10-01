from urllib.request import urlopen as open_url


def fetch():
    return open_url("https://api.example.com/data")
