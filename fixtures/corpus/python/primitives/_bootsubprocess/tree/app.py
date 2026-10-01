import _bootsubprocess


def probe():
    return _bootsubprocess._waitstatus_to_exitcode(0)
