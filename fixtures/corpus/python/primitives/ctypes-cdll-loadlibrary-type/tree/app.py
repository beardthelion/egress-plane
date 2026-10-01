import ctypes


def probe(target):
    return ctypes.cdll.LoadLibrary(target)
