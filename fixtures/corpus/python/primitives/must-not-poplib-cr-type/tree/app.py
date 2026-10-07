from poplib import CR, CRLF, HAVE_SSL, LF, POP3_PORT, POP3_SSL_PORT, _MAXLINE, error_proto

def probe():
    return (
        CR,
        CRLF,
        HAVE_SSL,
        LF,
        POP3_PORT,
        POP3_SSL_PORT,
        _MAXLINE,
        error_proto,
    )
