package main

import pkg "github.com/segmentio/kafka-go"

func probe() {
    pkg.DialLeader("x", "x", "x.example:443")
}
