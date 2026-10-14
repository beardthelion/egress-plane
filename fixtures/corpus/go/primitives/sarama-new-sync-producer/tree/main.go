package main

import "github.com/IBM/sarama"

func main() {
	p, err := sarama.NewSyncProducer([]string{"broker.example.com:9092"}, nil)
	_ = err
	_ = p
}
