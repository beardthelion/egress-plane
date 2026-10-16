package main

import pkg "net/http/httputil"

func probe() {
    pkg.NewSingleHostReverseProxy("https://x.example/")
}
