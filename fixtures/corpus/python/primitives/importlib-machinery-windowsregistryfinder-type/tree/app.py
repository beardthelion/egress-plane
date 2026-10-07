import importlib

def probe():
    return importlib.machinery.WindowsRegistryFinder
