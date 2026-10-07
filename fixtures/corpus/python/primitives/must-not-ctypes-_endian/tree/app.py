from ctypes import _endian, macholib, wintypes

def probe():
    return (
        _endian,
        macholib,
        wintypes,
    )
