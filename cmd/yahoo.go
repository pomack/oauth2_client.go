package main

import (
    "github.com/pomack/oauth2_client"
)

func NewYahooOauth2ClientTester(properties oauth2_client.Properties) oauth2_client.OAuth2Client {
    c := oauth2_client.NewYahooClient()
    c.Initialize(properties)
    return c
}
