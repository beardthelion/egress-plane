package main

import (
	"context"

	"cloud.google.com/go/storage"
)

func main() {
	c, err := storage.NewClient(context.Background())
	_ = err
	_ = c
}
