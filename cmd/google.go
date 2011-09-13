package main

import (
    "github.com/pomack/oauth2_client"
)

type GoogleOauth2ClientTester struct {
    client *oauth2_client.GoogleClient
}

func NewGoogleOauth2ClientTester(properties oauth2_client.Properties) *oauth2_client.GoogleClient {
    c := oauth2_client.NewGoogleClient()
    c.Initialize(properties)
    return c
}
