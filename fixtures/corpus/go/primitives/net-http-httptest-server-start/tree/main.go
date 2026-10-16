package main

import pkg "net/http/httptest"

func probe() {
    var v pkg.Server
    v.Start()
}
