def make_client():
    return object()


def probe(name, u):
    c = make_client()
    return getattr(c, name)(u)
