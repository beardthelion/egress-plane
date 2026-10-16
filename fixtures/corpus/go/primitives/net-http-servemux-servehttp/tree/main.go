package main

import pkg "net/http"

func probe() {
    var v pkg.ServeMux
    v.ServeHTTP()
}
