package main

import pkg "net"

func main() {
    _ = pkg.Dialer.MultipathTCP
    _ = pkg.Dialer.SetMultipathTCP
    _ = pkg.ListenConfig.MultipathTCP
    _ = pkg.ListenConfig.SetMultipathTCP
}
