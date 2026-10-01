import os


def probe(target):
    return os.execlp(target)
