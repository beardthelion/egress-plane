import smtpd


def probe():
    return smtpd.SMTPServer()
