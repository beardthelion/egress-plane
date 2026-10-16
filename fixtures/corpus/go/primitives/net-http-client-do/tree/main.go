package main

import pkg "net/http"

func probe() {
    var v pkg.Client
    v.Do("https://x.example/")
}
