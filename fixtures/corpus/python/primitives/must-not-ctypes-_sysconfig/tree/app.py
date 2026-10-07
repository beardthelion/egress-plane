from ctypes import _sysconfig

def probe():
    return (
        _sysconfig,
    )
