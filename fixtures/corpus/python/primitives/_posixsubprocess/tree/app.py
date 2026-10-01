import _posixsubprocess


def probe():
    return _posixsubprocess.fork_exec()
