import grpc


def probe():
    return grpc.aio.server()
