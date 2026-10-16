package main

import pkg "github.com/segmentio/kafka-go"

func probe() {
    var v pkg.Dialer
    v.DialContext()
}
