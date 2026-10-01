import os


def probe(target):
    return os.spawnl(None, target)
