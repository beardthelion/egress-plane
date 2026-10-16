package main

import pkg "github.com/Azure/azure-sdk-for-go/sdk/azidentity"

func probe() {
    pkg.NewDefaultAzureCredential()
}
