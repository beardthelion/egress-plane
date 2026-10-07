import importlib

def probe():
    return importlib.abc.__getattr__
