import platform


def probe():
    return platform._syscmd_file()
