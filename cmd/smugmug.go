package main

import (
    "github.com/pomack/oauth2_client"
)

func NewSmugMugOauth2ClientTester(properties oauth2_client.Properties) oauth2_client.OAuth2Client {
    c := oauth2_client.NewSmugMugClient()
    c.Initialize(properties)
    return c
}
