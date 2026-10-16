package main

import pkg "github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"

func probe() {
    pkg.NewClientWithSharedKeyCredential("https://x.example/")
}
