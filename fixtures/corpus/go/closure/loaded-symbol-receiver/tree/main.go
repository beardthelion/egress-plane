package main

import "plugin"

func lookup(name string) any { return func(string) {} }

func probe(name string) {
	p, _ := plugin.Open(name)
	sym, _ := p.Lookup(name)
	sym.(func(string))("x")
}
