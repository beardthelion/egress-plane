import requests


class Api:
    def get(self, path):
        return requests.get(path)
