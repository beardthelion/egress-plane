import httpx


def list_items():
    return httpx.get("https://api.example.com/items").json()
