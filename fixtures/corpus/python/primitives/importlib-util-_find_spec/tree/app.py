import importlib

def probe():
    return importlib.util._find_spec
