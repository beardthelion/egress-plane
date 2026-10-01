import _winapi


def probe():
    return _winapi.CreateProcess()
