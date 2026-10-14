package main

import "net/http"

func main() {
	var t http.Transport
	t.RoundTrip(nil)
	t2 := http.Transport{}
	t2.RoundTrip(nil)
}
