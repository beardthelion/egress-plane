import grpc


def probe(target):
    return grpc.secure_channel(target)
