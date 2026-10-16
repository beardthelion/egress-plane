package main

import pkg "net/http"

func probe() {
    pkg.NewRequestWithContext("x", "x", "https://x.example/")
}
