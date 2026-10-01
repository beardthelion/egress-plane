import requests

CONFIG = requests.get("https://api.example.com/boot").json()
