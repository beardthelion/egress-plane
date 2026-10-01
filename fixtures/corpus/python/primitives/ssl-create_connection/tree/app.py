import ssl


def probe():
    return ssl.create_connection(("api.example.test", 443))
