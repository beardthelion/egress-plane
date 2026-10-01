import os


def probe(target):
    return os._spawnvef(None, target)
