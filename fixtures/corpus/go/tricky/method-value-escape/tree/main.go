package main

import "net/http"

func fetch() {
	f := http.Get
	run(http.Get)
}
