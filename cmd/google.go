package main

import (
    "github.com/pomack/oauth2_client"
)

func NewGoogleOauth2ClientTester(properties oauth2_client.Properties) oauth2_client.OAuth2Client {
    c := oauth2_client.NewGoogleClient()
    c.Initialize(properties)
    return c
}
