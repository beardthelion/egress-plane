package main

import "google.golang.org/grpc"

func main() {
	conn, err := grpc.Dial("grpc.example.com:443")
	_ = err
	_ = conn
}
