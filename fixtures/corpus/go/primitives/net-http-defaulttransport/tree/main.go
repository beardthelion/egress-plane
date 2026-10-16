package main

import pkg "net/http"

func probe() {
    pkg.DefaultTransport()
}
