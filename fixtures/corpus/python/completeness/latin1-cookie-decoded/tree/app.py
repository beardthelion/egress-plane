# coding: latin-1

import urllib.request

def fetch():
    name = 'café'
    urllib.request.urlopen('https://api.example.com/' + name)
