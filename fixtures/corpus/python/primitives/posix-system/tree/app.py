import posix


def probe(target):
    return posix.system(target)
