package main

import pkg "net/http/httptrace"

func probe() {
    pkg.ClientTrace()
}
