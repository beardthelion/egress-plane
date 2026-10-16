package main

import pkg "net/http"

func probe() {
    var v pkg.Server
    v.ListenAndServeTLS()
}
