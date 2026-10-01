import socket


def probe():
    conn = socket.create_connection(("api.example.com", 443), timeout=3)
    conn.close()
