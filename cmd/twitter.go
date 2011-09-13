package main

import (
    "github.com/pomack/oauth2_client"
)

type TwitterOauth2ClientTester struct {
    client *oauth2_client.TwitterClient
}

func NewTwitterOauth2ClientTester(properties oauth2_client.Properties) *oauth2_client.TwitterClient {
    c := oauth2_client.NewTwitterClient()
    c.Initialize(properties)
    return c
}
