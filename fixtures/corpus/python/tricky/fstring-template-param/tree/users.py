import requests


def get_user(user_id):
    return requests.get(f"https://api.example.com/users/{user_id}")
