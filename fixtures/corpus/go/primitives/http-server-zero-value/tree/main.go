package main

import "net/http"

func main() {
	var s http.Server
	s.ListenAndServe()
	s2 := http.Server{Addr: ":8080"}
	s2.ListenAndServe()
}
