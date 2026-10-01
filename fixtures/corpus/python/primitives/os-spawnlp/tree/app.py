import os


def probe(target):
    return os.spawnlp(None, target)
