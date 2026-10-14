package main

import "database/sql"

func main() {
	db := sql.OpenDB(nil)
	_ = db
}
