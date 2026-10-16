package main

import pkg "net/http/httptest"

func probe() {
    pkg.NewTLSServer()
}
