package main

import pkg "net/http/cookiejar"

func probe() {
    var v pkg.Jar
    v.Cookies("https://x.example/")
}
