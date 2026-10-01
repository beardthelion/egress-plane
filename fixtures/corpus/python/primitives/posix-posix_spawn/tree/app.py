import posix


def probe(target):
    return posix.posix_spawn(target)
