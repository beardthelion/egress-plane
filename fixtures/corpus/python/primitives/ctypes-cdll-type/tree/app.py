import ctypes


def probe(target):
    return ctypes.CDLL(target)
