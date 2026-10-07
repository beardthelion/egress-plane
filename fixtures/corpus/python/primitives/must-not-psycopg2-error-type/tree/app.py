from psycopg2 import DataError, DatabaseError, Error, IntegrityError, InterfaceError, InternalError, NotSupportedError, OperationalError, ProgrammingError, Warning, errors

def probe():
    return (
        Error,
        Warning,
        DatabaseError,
        OperationalError,
        IntegrityError,
        InterfaceError,
        DataError,
        ProgrammingError,
        InternalError,
        NotSupportedError,
        errors,
    )
