package main

import "net/http"

func main() {
	s := make([]http.Client, 4)
	_ = s
}
