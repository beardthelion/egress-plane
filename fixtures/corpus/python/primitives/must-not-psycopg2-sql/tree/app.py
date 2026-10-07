from psycopg2 import BINARY, Binary, DATETIME, Date, DateFromTicks, NUMBER, ROWID, STRING, Time, TimeFromTicks, Timestamp, TimestampFromTicks, __version__, apilevel, paramstyle, sql, threadsafety

def probe():
    return (
        sql,
        Binary,
        Date,
        Time,
        Timestamp,
        DateFromTicks,
        TimeFromTicks,
        TimestampFromTicks,
        STRING,
        BINARY,
        NUMBER,
        DATETIME,
        ROWID,
        apilevel,
        paramstyle,
        threadsafety,
        __version__,
    )
