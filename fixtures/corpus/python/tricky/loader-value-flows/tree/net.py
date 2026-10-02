mod, retries = __import__("subprocess"), 3


def pick(fast):
    sock = __import__("socket") if fast else None
    return sock


def spawn(cmd):
    mod.run(cmd)
