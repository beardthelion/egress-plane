package main

import pkg "plugin"

func probe() {
    var v pkg.Plugin
    v.Lookup()
}
