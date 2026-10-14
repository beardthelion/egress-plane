package main

import "database/sql"

type myDriver struct{}

func main() {
	sql.Register("mydrv", myDriver{})
}
