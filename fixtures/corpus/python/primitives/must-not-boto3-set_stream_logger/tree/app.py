from boto3 import NullHandler, __version__, set_stream_logger

def probe():
    return (
        NullHandler,
        __version__,
        set_stream_logger,
    )
