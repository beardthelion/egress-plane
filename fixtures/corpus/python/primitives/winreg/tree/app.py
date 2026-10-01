import winreg


def probe():
    return winreg.ConnectRegistry()
