import os

from flask import Flask

import requests

app = Flask(__name__)


@app.route("/proxy")
def proxy():
    return requests.get(os.environ["UPSTREAM_URL"]).text
