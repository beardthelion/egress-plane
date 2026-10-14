package main

import "github.com/go-sql-driver/mysql"

func main() {
	c, err := mysql.NewConnector(nil)
	_ = err
	_ = c
}
