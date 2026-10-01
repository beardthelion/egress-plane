import xmlrpc.client


def probe():
    return xmlrpc.client.SafeTransport()
