import importlib

# Preload modules for their import side effects; the values are discarded.
importlib.import_module("subprocess")
__import__("socket")


def warm():
    __import__("ssl")
    importlib.import_module("http.client")
