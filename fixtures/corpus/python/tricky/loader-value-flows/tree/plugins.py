import importlib


def load():
    return importlib.import_module("subprocess")


def run_job(cmd):
    load().run(cmd)
