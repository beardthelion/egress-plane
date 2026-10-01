import ctypes.util


def probe():
    return ctypes.util._get_soname()
