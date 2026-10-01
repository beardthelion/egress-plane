import os


def probe(target):
    return os.spawnlpe(None, target)
