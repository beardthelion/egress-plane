package main

import "net/http/httptest"

func main() {
	var r httptest.ResponseRecorder
	_ = r
	_ = httptest.NewRecorder
	_ = httptest.DefaultRemoteAddr
	_ = httptest.ResponseRecorder.Code
	_ = httptest.Server.Addr
}
