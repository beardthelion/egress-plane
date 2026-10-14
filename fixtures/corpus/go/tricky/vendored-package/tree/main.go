package main

import (
	"net/http"
	"github.com/acme/vlib"
)

func main() {
	http.Get(vlib.URL)
}
