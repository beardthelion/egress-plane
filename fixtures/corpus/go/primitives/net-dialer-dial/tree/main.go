package main

import pkg "net"

func probe() {
    var v pkg.Dialer
    v.Dial("x", "x.example:443")
}
