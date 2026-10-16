package main

import pkg "golang.org/x/crypto/ssh"

func probe() {
    var v pkg.Client
    v.NewSession()
}
