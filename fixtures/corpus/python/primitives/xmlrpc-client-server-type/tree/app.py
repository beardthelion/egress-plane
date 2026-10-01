import xmlrpc.client


def probe(target):
    return xmlrpc.client.Server(target)
