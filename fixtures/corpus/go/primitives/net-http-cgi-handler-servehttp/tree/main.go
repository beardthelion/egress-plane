package main

import pkg "net/http/cgi"

func probe() {
    var v pkg.Handler
    v.ServeHTTP()
}
