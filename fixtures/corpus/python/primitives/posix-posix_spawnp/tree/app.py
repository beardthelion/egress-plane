import posix


def probe(target):
    return posix.posix_spawnp(target)
