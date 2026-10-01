import os


def probe(target):
    return os.execle(target)
