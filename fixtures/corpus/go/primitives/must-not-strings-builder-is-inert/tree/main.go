package main

import "strings"

func main() {
	var b strings.Builder
	b.WriteString("nats://nats.example.com:4222")
	_ = b.String()
}
