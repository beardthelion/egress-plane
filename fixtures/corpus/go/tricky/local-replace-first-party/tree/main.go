package main

import (
	"net/http"
	"github.com/acme/lib"
)

func main() {
	http.Get(lib.URL)
}
