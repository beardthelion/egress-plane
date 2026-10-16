package main

import pkg "github.com/Azure/azure-sdk-for-go/sdk/azcore"

func probe() {
    pkg.NewClient()
}
