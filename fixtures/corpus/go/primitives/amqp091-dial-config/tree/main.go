package main

import amqp "github.com/rabbitmq/amqp091-go"

func main() {
	c, err := amqp.DialConfig("amqp://mq.example.com:5672/", amqp.Config{})
	_ = err
	_ = c
}
