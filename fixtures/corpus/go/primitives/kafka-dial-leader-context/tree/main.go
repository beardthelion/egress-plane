package main

import pkg "github.com/segmentio/kafka-go"

func probe() {
    pkg.DialLeaderContext("x", "x", "x.example:443")
}
