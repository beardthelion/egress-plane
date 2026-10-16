package main

import pkg "github.com/rabbitmq/amqp091-go"

func probe() {
    pkg.DialTLS("https://x.example/")
}
