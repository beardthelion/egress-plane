package main

import "net/http"

type Fake struct{}

func (f Fake) Get(u string) {}

func fetch(http Fake, u string) {
	http.Get(u)
}

func main() {
	fetch(Fake{}, "https://shadowed.example.com")
	_ = http.MethodGet
}
