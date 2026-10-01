import os


def probe(target):
    return os.spawnv(None, target)
