import os


def config_path(home):
    return os.path.join(home, ".config", "app.toml")


def exists(p):
    return os.path.exists(os.path.abspath(p))
