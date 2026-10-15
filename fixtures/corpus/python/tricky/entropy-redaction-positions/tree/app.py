import urllib.request


def probe():
    urllib.request.urlopen("https://api.example.com/x?u=aB3xK9mZ2vN8pQ4wE7rT6yU5zA1c2d&page=2")
    urllib.request.urlopen("https://api.example.com/aB3xK9mZ2vN8pQ4wE7rT6yU5zA1c2d/v2")
    urllib.request.urlopen("https://api.example.com/a1b2c3d4e5f6a7b8c9d0a1b2c3d4e5f6a7b8/v2")
