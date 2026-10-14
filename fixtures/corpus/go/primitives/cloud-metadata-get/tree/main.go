package main

import "cloud.google.com/go/compute/metadata"

func main() {
	v, err := metadata.Get("instance/zone")
	_ = err
	_ = v
}
