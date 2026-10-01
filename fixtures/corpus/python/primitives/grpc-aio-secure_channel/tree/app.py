import grpc


def probe(target):
    return grpc.aio.secure_channel(target)
