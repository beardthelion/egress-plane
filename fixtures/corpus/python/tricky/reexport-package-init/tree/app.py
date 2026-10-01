from net import post


def emit():
    return post("https://api.example.com/events", json={})
