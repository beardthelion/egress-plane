import http.client

def connect():
    return http.client.HTTPConnection('egress.example')
