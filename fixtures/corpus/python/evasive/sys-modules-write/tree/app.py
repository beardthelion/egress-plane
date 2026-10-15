import sys

TABLE = {}


def probe(name):
    sys.modules[name] = name
