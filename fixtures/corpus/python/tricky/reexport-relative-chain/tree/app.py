from client import create_connection


def connect_db():
    return create_connection(("db.example.com", 5432))
