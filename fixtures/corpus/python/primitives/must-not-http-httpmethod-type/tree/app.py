from http import HTTPMethod, HTTPStatus, IntEnum, StrEnum, _simple_enum

def probe():
    return (
        HTTPMethod,
        HTTPStatus,
        IntEnum,
        StrEnum,
        _simple_enum,
    )
