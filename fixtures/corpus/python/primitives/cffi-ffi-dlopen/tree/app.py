import cffi


def probe(target):
    s = cffi.FFI()
    return s.dlopen(target)
