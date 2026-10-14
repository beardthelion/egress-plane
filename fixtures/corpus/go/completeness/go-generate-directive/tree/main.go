package main

//go:generate stringer -type=Pill

type Pill int

// go:generate not-a-directive
	//go:generate indented

func main() {}

//go:generate go run gen.go
