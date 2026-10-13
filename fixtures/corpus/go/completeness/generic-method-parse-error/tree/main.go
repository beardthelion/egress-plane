package main

type R struct{}

func (r *R) N[T any]() T {
	var zero T
	return zero
}

func main() {}
