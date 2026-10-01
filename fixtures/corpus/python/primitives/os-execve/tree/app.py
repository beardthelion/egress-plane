import os


def probe(target):
    return os.execve(target)
