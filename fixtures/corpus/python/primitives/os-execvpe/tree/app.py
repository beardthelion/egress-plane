import os


def probe(target):
    return os.execvpe(target)
