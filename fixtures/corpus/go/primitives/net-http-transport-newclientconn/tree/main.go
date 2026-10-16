package main

import pkg "net/http"

func probe() {
    var v pkg.Transport
    v.NewClientConn()
}
