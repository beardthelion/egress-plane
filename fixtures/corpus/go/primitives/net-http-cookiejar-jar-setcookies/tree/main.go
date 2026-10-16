package main

import pkg "net/http/cookiejar"

func probe() {
    var v pkg.Jar
    v.SetCookies("https://x.example/")
}
