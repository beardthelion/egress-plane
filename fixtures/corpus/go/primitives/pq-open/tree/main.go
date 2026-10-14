package main

import "github.com/lib/pq"

func main() {
	c, err := pq.Open("postgres://db.example.com:5432/app")
	_ = err
	_ = c
}
