package main

import pkg "net/http/httptest"

func main() {
    _ = pkg.DefaultRemoteAddr
    _ = pkg.NewReExample
    _ = pkg.ResponseRecorder
    _ = pkg.ResponseRecorder.Example
    _ = pkg.Server.Example
}
