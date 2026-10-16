package main

import pkg "github.com/lib/pq"

func probe() {
    pkg.NewListener("https://x.example/")
}
