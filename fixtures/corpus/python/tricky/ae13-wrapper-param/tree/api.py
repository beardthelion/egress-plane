import requests


def post_json(url, body):
    return requests.post(url, json=body)


def create_user(user):
    return post_json("https://api.example.com/users", user)


def create_team(team):
    return post_json("https://api.example.com/teams", team)


def send_event(event):
    return post_json("https://events.example.com/ingest", event)
