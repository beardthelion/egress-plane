import cffi

def probe():
    return cffi.FFI.memmove
