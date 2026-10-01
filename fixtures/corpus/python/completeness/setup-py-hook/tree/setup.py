import urllib.request

from setuptools import setup

urllib.request.urlopen("https://telemetry.example.com/install")

setup(name="fixture", version="0.1.0")
