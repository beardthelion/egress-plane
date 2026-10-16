package main

import pkg "github.com/go-sql-driver/mysql"

func probe() {
    pkg.MySQLDriver()
}
