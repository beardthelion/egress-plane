import http.server


def probe():
    return http.server.HTTPServer()
