import os


def probe(target):
    return os.execv(target)
