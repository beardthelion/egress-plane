import grpc


def probe(target):
    return grpc.insecure_channel(target)
