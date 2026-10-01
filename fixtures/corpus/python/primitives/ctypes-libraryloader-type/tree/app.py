import ctypes


def probe():
    return ctypes.LibraryLoader()
