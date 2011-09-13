package main

import (
    "github.com/pomack/oauth2_client"
)

type FacebookOauth2ClientTester struct {
    client *oauth2_client.FacebookClient
}

func NewFacebookOauth2ClientTester(properties oauth2_client.Properties) *oauth2_client.FacebookClient {
    c := oauth2_client.NewFacebookClient()
    c.Initialize(properties)
    return c
}
