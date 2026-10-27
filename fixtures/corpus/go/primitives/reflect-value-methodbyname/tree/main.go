package main

import pkg "reflect"

func probe() {
    var v pkg.Value
    v.MethodByName()
}
