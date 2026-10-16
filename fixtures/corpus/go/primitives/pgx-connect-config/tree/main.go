package main

import pkg "github.com/jackc/pgx/v5"

func probe() {
    pkg.ConnectConfig()
}
