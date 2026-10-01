import os


def probe(target):
    return os._execvpe(target)
