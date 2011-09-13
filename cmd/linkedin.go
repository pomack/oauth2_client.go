package main

import (
    "github.com/pomack/oauth2_client"
)

type LinkedInOauth2ClientTester struct {
    client *oauth2_client.LinkedInClient
}

func NewLinkedInOauth2ClientTester(properties oauth2_client.Properties) *oauth2_client.LinkedInClient {
    c := oauth2_client.NewLinkedInClient()
    c.Initialize(properties)
    return c
}
