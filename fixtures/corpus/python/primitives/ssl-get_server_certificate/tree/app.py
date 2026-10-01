import ssl


def probe():
    return ssl.get_server_certificate(("api.example.test", 443))
