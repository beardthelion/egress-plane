package main

import "net/http/httptest"

func main() {
	var r httptest.ResponseRecorder
	_ = r
	_ = httptest.NewRecorder
	_ = httptest.DefaultRemoteAddr
}
