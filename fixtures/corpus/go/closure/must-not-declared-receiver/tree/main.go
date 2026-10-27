package main

import "plugin"

func lookup(name string) any { return func(string) {} }

func probe(name string) {
	p, _ := lookup(name)
	sym, _ := p.Lookup(name)
	sym.(func(string))("x")
}
