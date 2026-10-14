package main

import (
	"net/http"
	"net/http/cgi"
)

func main() {
	h := cgi.Handler{Path: "/usr/bin/env"}
	http.ListenAndServe(":8080", h)
}
