package main

import "net/http/httputil"

func main() {
	var p httputil.ReverseProxy
	p.ServeHTTP(nil, nil)
	p2 := httputil.ReverseProxy{}
	p2.ServeHTTP(nil, nil)
}
