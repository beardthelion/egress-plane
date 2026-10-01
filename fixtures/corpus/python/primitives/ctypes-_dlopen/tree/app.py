import ctypes


def probe(target):
    return ctypes._dlopen(target)
