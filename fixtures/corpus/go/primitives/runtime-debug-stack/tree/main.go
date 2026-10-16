package main

import pkg "runtime/debug"

func probe() {
    pkg.Stack()
}
