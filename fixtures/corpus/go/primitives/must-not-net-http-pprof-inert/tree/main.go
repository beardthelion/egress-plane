package main

import "net/http/pprof"

// The internal handler.ServeHTTP member stays inert; the exported
// handlers are classified.
func main() {
	var _ = pprof.Lookup
	_ = pprof.handler.ServeHTTP
}
