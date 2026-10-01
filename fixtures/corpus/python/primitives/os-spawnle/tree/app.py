import os


def probe(target):
    return os.spawnle(None, target)
