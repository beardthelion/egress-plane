package main

import pkg "github.com/rabbitmq/amqp091-go"

func probe() {
    var v pkg.Channel
    v.Consume("https://x.example/")
}
