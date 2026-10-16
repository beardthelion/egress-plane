package main

import pkg "github.com/jackc/pgx/v5/pgxpool"

func probe() {
    pkg.New("x", "https://x.example/")
}
