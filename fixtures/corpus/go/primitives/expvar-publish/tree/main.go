package main

import "expvar"

func main() {
	expvar.Publish("hits", expvar.NewInt("hits"))
}
