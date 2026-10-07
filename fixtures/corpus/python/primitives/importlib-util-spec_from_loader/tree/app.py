import importlib

def probe():
    return importlib.util.spec_from_loader
