package main

import (
	"context"

	"github.com/jackc/pgx/v5"
)

func main() {
	c, err := pgx.Connect(context.Background(), "postgres://db.example.com:5432/app")
	_ = err
	_ = c
}
