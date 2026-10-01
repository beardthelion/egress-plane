import pty


def probe(target):
    return pty.spawn(target)
