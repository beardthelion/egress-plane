import uuid


def probe():
    return uuid._get_command_stdout()
