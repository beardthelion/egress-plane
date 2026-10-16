package main

import pkg "net/http/httputil"

func probe() {
    pkg.NewClientConn()
}
