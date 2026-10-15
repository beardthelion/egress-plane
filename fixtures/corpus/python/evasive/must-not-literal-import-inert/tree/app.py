def probe(name, u):
    m = __import__("json")
    return getattr(m, "member")(u)
