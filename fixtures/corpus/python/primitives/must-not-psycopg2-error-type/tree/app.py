from psycopg2 import DataError, DatabaseError, Error, IntegrityError, InterfaceError, InternalError, NotSupportedError, OperationalError, ProgrammingError, Warning, errors

def probe():
    return (
        DataError,
        DatabaseError,
        Error,
        IntegrityError,
        InterfaceError,
        InternalError,
        NotSupportedError,
        OperationalError,
        ProgrammingError,
        Warning,
        errors,
    )
