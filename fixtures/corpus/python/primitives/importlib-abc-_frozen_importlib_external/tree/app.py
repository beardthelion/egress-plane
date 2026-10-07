import importlib

def probe():
    return importlib.abc._frozen_importlib_external
