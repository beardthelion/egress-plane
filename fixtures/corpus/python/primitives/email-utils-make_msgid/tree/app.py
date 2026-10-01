import email.utils


def probe():
    return email.utils.make_msgid()
