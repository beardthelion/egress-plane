package main

import pkg "github.com/jackc/pgx/v5/pgconn"

func probe() {
    pkg.Connect("x", "https://x.example/")
}
