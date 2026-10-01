import ctypes


def probe(target):
    return ctypes.PyDLL(target)
