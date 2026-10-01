import os


def probe(target):
    return os.popen(target)
