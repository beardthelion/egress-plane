import importlib

def probe():
    return importlib.util._module_to_load
