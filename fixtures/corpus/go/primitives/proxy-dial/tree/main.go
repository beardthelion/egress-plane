package main

import pkg "golang.org/x/net/proxy"

func probe() {
    pkg.Dial("x", "x.example:443")
}
