import ctypes


def probe(load_library):
    return load_library("libprobe.so")
