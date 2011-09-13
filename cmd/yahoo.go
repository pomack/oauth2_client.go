package main

import (
    "github.com/pomack/oauth2_client"
)

type YahooOauth2ClientTester struct {
    client *oauth2_client.YahooClient
}

func NewYahooOauth2ClientTester(properties oauth2_client.Properties) *oauth2_client.YahooClient {
    c := oauth2_client.NewYahooClient()
    c.Initialize(properties)
    return c
}
