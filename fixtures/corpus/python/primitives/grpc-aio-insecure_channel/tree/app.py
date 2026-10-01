import grpc


def probe(target):
    return grpc.aio.insecure_channel(target)
