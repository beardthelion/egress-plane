package main

import pkg "net/http"

func probe() {
    pkg.ListenAndServeTLS("x.example:443")
}
