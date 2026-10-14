package main

import "database/sql"

func main() {
	db, err := sql.Open("pgx", "postgres://db.example.com:5432/app")
	_ = err
	_ = db
}
