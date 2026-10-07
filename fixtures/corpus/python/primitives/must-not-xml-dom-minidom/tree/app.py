from xml.dom import NodeFilter, expatbuilder, minicompat, minidom, pulldom

def probe():
    return (
        minidom,
        pulldom,
        expatbuilder,
        minicompat,
        NodeFilter,
    )
