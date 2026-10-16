package main

import pkg "net/http/fcgi"

func probe() {
    pkg.Serve()
}
