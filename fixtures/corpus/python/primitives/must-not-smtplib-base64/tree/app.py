from smtplib import base64, copy, datetime, hmac, io, re

def probe():
    return (
        base64,
        copy,
        datetime,
        hmac,
        io,
        re,
    )
