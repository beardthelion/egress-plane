package main

import (
	"net/http"
	"strings"
)

func probe() {
	f := http.Get
	f("https://x.example/")
}
