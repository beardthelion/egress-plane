import httpx


class Api:
    def __init__(self):
        self.http = httpx.Client(base_url="https://api.example.com")

    def users(self):
        return self.http.get("/users")
