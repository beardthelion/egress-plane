from ctypes.util import _is_elf

def probe():
    return (
        _is_elf,
    )
