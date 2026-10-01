import posix


def probe(target):
    return posix.execv(target)
