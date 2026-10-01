import ctypes.util


def probe():
    return ctypes.util._findSoname_ldconfig()
