package main

import pkg "net/http"

func probe() {
    var v pkg.DefaultClient
    v.PostForm("https://x.example/")
}
