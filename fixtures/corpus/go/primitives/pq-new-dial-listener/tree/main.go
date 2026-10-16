package main

import pkg "github.com/lib/pq"

func probe() {
    pkg.NewDialListener()
}
