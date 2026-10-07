from logging.handlers import BaseRotatingHandler, BufferingHandler, DEFAULT_HTTP_LOGGING_PORT, DEFAULT_SOAP_LOGGING_PORT, DEFAULT_TCP_LOGGING_PORT, DEFAULT_UDP_LOGGING_PORT, MemoryHandler, NTEventLogHandler, QueueHandler, QueueListener, RotatingFileHandler, ST_DEV, ST_INO, ST_MTIME, SYSLOG_TCP_PORT, SYSLOG_UDP_PORT, TimedRotatingFileHandler, WatchedFileHandler, _MIDNIGHT

def probe():
    return (
        BaseRotatingHandler,
        BufferingHandler,
        DEFAULT_HTTP_LOGGING_PORT,
        DEFAULT_SOAP_LOGGING_PORT,
        DEFAULT_TCP_LOGGING_PORT,
        DEFAULT_UDP_LOGGING_PORT,
        MemoryHandler,
        NTEventLogHandler,
        QueueHandler,
        QueueListener,
        RotatingFileHandler,
        ST_DEV,
        ST_INO,
        ST_MTIME,
        SYSLOG_TCP_PORT,
        SYSLOG_UDP_PORT,
        TimedRotatingFileHandler,
        WatchedFileHandler,
        _MIDNIGHT,
    )
