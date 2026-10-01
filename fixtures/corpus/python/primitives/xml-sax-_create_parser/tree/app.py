import xml.sax


def probe():
    return xml.sax._create_parser()
