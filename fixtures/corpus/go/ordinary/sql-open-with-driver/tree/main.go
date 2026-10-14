package main

import (
	"database/sql"

	_ "github.com/lib/pq"
)

func main() {
	db, err := sql.Open("postgres", "postgres://db.example.com:5432/app")
	_ = err
	_ = db
}
