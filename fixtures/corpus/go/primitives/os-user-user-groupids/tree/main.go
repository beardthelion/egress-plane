package main

import pkg "os/user"

func probe() {
    var v pkg.User
    v.GroupIds()
}
