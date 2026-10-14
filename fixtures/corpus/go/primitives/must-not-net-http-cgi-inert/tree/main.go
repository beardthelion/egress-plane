package main

import "net/http/cgi"

// The unexported response and neverEnding.Read members stay inert.
func main() {
	var _ = cgi.Request
	var _ = cgi.RequestFromMap
	_ = cgi.response.Write
	_ = cgi.neverEnding.Read
}
