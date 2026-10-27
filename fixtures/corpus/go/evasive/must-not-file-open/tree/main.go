package main

import (
	"os"
	"plugin"
)

func probe(name string) {
	p, _ := os.Open(name)
	s, _ := p.Lookup(name)
	_ = s
}
