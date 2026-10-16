package main

import pkg "github.com/nats-io/nats.go"

func probe() {
    var v pkg.Conn
    v.Subscribe("https://x.example/")
}
