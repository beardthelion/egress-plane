package main

import (
	"context"

	"go.mongodb.org/mongo-driver/mongo"
)

func main() {
	c, err := mongo.Connect(context.Background())
	_ = err
	_ = c
}
