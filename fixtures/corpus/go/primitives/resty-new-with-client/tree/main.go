package main

import pkg "github.com/go-resty/resty"

func probe() {
    pkg.NewWithClient()
}
