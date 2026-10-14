package main

import "github.com/rabbitmq/amqp091-go"

func main() {
	conn, err := amqp091.Dial("amqp://guest:guest@mq.example.com:5672/")
	_ = err
	_ = conn
}
