import psycopg2
import requests
import urllib.request


def connect_first(h):
    return psycopg2.connect(password="PYPW1FAKE", host=h)


def connect_after_comma(h):
    return psycopg2.connect(host=h,password="HUNTER3PWFAKE")


def post_tuple(kw):
    return requests.post(**kw, auth=("admin", "HUNTER2PWFAKE"))


def request_header(u):
    return urllib.request.urlopen(urllib.request.Request(u, headers={"X-Api-Key": "HUNTER6PWFAKE"}))
