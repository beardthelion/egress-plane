package main

import pkg "net"

func probe() {
    var v pkg.Dialer
    v.DialTCP()
}
