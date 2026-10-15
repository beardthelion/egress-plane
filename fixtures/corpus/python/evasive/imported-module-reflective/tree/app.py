def probe(name, u):
    m = __import__(name)
    return getattr(m, "member")(u)
