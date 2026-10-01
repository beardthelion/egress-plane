import ctypes


def probe(target):
    return ctypes.pydll.LoadLibrary(target)
