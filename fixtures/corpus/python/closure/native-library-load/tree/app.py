import ctypes


def probe(load_library):
    return ctypes.CDLL("libprobe.so")
