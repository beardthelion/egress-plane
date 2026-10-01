import psycopg2


def probe(target):
    return psycopg2.extensions.connection(target)
