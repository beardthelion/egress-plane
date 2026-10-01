import sys

import requests

if sys.platform == "win32":
    def ping():
        return requests.get("https://api.example.com/ping")
else:
    def ping():
        return requests.get("https://api.example.com/ping")
