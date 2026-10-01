import ctypes.util


def probe():
    return ctypes.util.find_library()
