import requests


def fetch_all():
    session = requests.Session()
    a = session.get("https://api.example.com/a")
    b = session.post("https://api.example.com/b")
    return a, b
