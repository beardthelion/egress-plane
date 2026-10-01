import xmlrpc.server


def probe():
    return xmlrpc.server.SimpleXMLRPCServer()
