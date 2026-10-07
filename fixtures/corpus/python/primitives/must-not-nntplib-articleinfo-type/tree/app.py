from nntplib import ArticleInfo, GroupInfo, NNTPDataError, NNTPError, NNTPPermanentError, NNTPProtocolError, NNTPReplyError, NNTPTemporaryError, NNTP_PORT, NNTP_SSL_PORT, _CRLF, _DEFAULT_OVERVIEW_FMT, _GLOBAL_DEFAULT_TIMEOUT, _LONGRESP, _MAXLINE, _OVERVIEW_FMT_ALTERNATIVES, _email_decode_header, _encrypt_on, _have_ssl, _parse_datetime, _parse_overview, _parse_overview_fmt, _unparse_datetime, decode_header

def probe():
    return (
        ArticleInfo,
        GroupInfo,
        NNTPDataError,
        NNTPError,
        NNTPPermanentError,
        NNTPProtocolError,
        NNTPReplyError,
        NNTPTemporaryError,
        NNTP_PORT,
        NNTP_SSL_PORT,
        _CRLF,
        _DEFAULT_OVERVIEW_FMT,
        _GLOBAL_DEFAULT_TIMEOUT,
        _LONGRESP,
        _MAXLINE,
        _OVERVIEW_FMT_ALTERNATIVES,
        _email_decode_header,
        _encrypt_on,
        _have_ssl,
        _parse_datetime,
        _parse_overview,
        _parse_overview_fmt,
        _unparse_datetime,
        decode_header,
    )
