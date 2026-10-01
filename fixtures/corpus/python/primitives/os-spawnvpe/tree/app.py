import os


def probe(target):
    return os.spawnvpe(None, target)
