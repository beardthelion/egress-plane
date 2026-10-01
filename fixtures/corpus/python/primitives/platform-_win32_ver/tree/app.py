import platform


def probe():
    return platform._win32_ver()
