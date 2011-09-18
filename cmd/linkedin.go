package main

import (
    "github.com/pomack/jsonhelper"
    "github.com/pomack/oauth2_client"
)

func NewLinkedInOauth2ClientTester(properties jsonhelper.JSONObject) oauth2_client.OAuth2Client {
    c := oauth2_client.NewLinkedInClient()
    c.Initialize(properties)
    return c
}
