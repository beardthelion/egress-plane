from boto3 import NullHandler, __version__, set_stream_logger

def probe():
    return (
        set_stream_logger,
        NullHandler,
        __version__,
    )
