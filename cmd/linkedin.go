package main

import (
    "github.com/pomack/oauth2_client"
)

func NewLinkedInOauth2ClientTester(properties oauth2_client.JSONObject) oauth2_client.OAuth2Client {
    c := oauth2_client.NewLinkedInClient()
    c.Initialize(properties)
    return c
}
