package main

import pkg "net/http"

func probe() {
    pkg.Post("https://x.example/")
}
