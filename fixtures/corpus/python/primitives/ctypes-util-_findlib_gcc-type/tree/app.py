import ctypes.util


def probe():
    return ctypes.util._findLib_gcc()
