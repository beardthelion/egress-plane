package main

import pkg "github.com/go-resty/resty/v2"

func probe() {
    var v pkg.Client
    v.NewRequest()
}
