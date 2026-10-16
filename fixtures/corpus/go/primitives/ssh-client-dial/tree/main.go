package main

import pkg "golang.org/x/crypto/ssh"

func probe() {
    var v pkg.Client
    v.Dial("x", "x.example:443")
}
