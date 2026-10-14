package main

import "github.com/nats-io/nats.go"

func main() {
	_, _ = nats.Connect("nats://localhost:4222")
}
