import http.client


def open_conn():
    return http.client.HTTPSConnection("api.example.com")
