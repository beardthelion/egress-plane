package main

import pkg "github.com/go-sql-driver/mysql"

func probe() {
    var v pkg.MySQLDriver
    v.OpenConnector()
}
