package main

import (
    "github.com/pomack/jsonhelper.go/jsonhelper"
    "github.com/pomack/oauth2_client.go/oauth2_client"
)

func NewYahooOauth2ClientTester(properties jsonhelper.JSONObject) oauth2_client.OAuth2Client {
    c := oauth2_client.NewYahooClient()
    c.Initialize(properties)
    return c
}
