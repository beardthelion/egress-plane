import xml.sax


def probe(target):
    return xml.sax.parse(target)
