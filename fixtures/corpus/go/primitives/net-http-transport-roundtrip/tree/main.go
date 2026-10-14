package main

import "net/http"

func main() {
	var t http.Transport
	var req *http.Request
	r, err := t.RoundTrip(req)
	_ = err
	_ = r
}
