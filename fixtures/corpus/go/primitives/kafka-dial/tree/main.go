package main

import "github.com/segmentio/kafka-go"

func main() {
	c, err := kafka.Dial("tcp", "broker.example.com:9092")
	_ = err
	_ = c
}
