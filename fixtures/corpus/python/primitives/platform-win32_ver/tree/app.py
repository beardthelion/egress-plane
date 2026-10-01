import platform


def probe():
    return platform.win32_ver()
