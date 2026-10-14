package main

import "github.com/nats-io/nats.go"

func main() {
	nc, err := nats.Connect("nats://nats.example.com:4222")
	_ = err
	_ = nc
}
