package main

import pkg "net/smtp"

func probe() {
    var v pkg.Client
    v.Verify()
}
