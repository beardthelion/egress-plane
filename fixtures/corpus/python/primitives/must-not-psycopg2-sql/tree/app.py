from psycopg2 import BINARY, Binary, DATETIME, Date, DateFromTicks, NUMBER, ROWID, STRING, Time, TimeFromTicks, Timestamp, TimestampFromTicks, __version__, apilevel, paramstyle, sql, threadsafety

def probe():
    return (
        BINARY,
        Binary,
        DATETIME,
        Date,
        DateFromTicks,
        NUMBER,
        ROWID,
        STRING,
        Time,
        TimeFromTicks,
        Timestamp,
        TimestampFromTicks,
        __version__,
        apilevel,
        paramstyle,
        sql,
        threadsafety,
    )
