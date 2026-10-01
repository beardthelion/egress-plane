import os


def probe(target):
    return os.execl(target)
