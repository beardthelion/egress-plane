package main

import pkg "net/http/cgi"

func main() {
    _ = pkg.Request
    _ = pkg.RequestFromMap
    _ = pkg.neverEnding.Read
    _ = pkg.response.Example
}
