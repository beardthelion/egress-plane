package main

import pkg "github.com/IBM/sarama"

func probe() {
    pkg.NewBroker("x.example:443")
}
