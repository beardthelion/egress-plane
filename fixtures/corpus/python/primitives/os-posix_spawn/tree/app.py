import os


def probe(target):
    return os.posix_spawn(target)
