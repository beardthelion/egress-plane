import posix


def probe(target):
    return posix.execve(target)
