package main

import "net/http"

func main() {
	var s http.Server
	err := s.ListenAndServe()
	_ = err
}
