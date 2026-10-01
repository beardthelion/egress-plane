import os


def probe(target):
    return os.spawnve(None, target)
