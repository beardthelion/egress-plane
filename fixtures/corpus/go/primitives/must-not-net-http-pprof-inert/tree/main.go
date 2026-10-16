package main

import pkg "net/http/pprof"

func main() {
    _ = pkg.handler.ServeHTTP
}
