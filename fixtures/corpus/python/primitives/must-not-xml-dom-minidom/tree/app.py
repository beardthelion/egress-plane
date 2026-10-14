from xml.dom import NodeFilter, expatbuilder, minicompat, minidom, pulldom

def probe():
    return (
        NodeFilter,
        expatbuilder,
        minicompat,
        minidom,
        pulldom,
    )
