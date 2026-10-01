import os


def probe(target):
    return os.spawnvp(None, target)
