package main

import "github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"

func main() {
	c, err := azblob.NewClient("https://acct.blob.core.windows.net/", nil, nil)
	_ = err
	_ = c
}
