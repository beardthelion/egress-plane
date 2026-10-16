package main

import pkg "database/sql/driver"

func probe() {
    pkg.Connector()
}
