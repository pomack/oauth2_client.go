package main

import (
    "github.com/pomack/oauth2_client"
    "http"
    "io"
    "json"
    "log"
    "os"
    "strings"
    "url"
)

const (
    HOMEPAGE = `<?xml version="1.0" encoding="utf-8"?>
<html>
    <head>
        <title>OAuth Test Homepage</title>
    </head>
    <body>
        <h1>OAuth Test Homepage</h1>
        <p>
            <a href="/facebook">Test Facebook OAuth</a><br/>
            <a href="/google">Test Google OAuth</a><br/>
            <a href="/linkedin">Test LinkedIn OAuth</a><br/>
            <a href="/smugmug">Test SmugMug OAuth</a><br/>
            <a href="/twitter">Test Twitter OAuth</a><br/>
            <a href="/yahoo">Test Yahoo! OAuth</a><br/>
        </p>
    </body>
</html>`
)

func HandlePage(w http.ResponseWriter, req *http.Request) {
    w.Header().Set("Content-Type", "text/html")
    w.WriteHeader(200)
    io.WriteString(w, HOMEPAGE)
}

func HandleGenericOauthRequest(c oauth2_client.OAuth2Client, w http.ResponseWriter, req *http.Request) {
    uri := c.GenerateRequestTokenUrl(make(oauth2_client.JSONObject))
    if len(uri) > 0 {
        w.Header().Set("Location", uri)
        w.WriteHeader(302)
    } else {
        w.WriteHeader(500)
    }
}

func HandleFacebookOauthRequest(w http.ResponseWriter, req *http.Request) {
    c := NewFacebookOauth2ClientTester(getProperties())
    HandleGenericOauthRequest(c, w, req)
}

func HandleGoogleOauthRequest(w http.ResponseWriter, req *http.Request) {
    c := NewGoogleOauth2ClientTester(getProperties())
    HandleGenericOauthRequest(c, w, req)
}

func HandleLinkedInOauthRequest(w http.ResponseWriter, req *http.Request) {
    c := NewLinkedInOauth2ClientTester(getProperties())
    HandleGenericOauthRequest(c, w, req)
}

func HandleSmugMugOauthRequest(w http.ResponseWriter, req *http.Request) {
    c := NewSmugMugOauth2ClientTester(getProperties())
    HandleGenericOauthRequest(c, w, req)
}

func HandleTwitterOauthRequest(w http.ResponseWriter, req *http.Request) {
    c := NewTwitterOauth2ClientTester(getProperties())
    HandleGenericOauthRequest(c, w, req)
}

func HandleYahooOauthRequest(w http.ResponseWriter, req *http.Request) {
    c := NewYahooOauth2ClientTester(getProperties())
    HandleGenericOauthRequest(c, w, req)
}

func HandleClientAccept(w http.ResponseWriter, req *http.Request) {
    var c oauth2_client.OAuth2Client = nil
    method := "GET"
    headers := make(http.Header)
    uri := ""
    query := make(url.Values)
    var reader io.Reader = nil
    props := getProperties()
    q := req.URL.Query()
    log.Print("=================================")
    log.Print("Received request from User: ")
    reqBytes, _ := http.DumpRequest(req, true)
    log.Print(string(reqBytes))
    log.Print("=================================")
    if site := q.Get("site"); len(site) > 0 {
        if index := strings.Index(site, "?"); index >= 0 {
            site = site[0:index]
        }
        switch site {
        case "facebook.com":
            c = NewFacebookOauth2ClientTester(props)
            uri = props.GetAsString("facebook.client.test_url")
        case "google.com":
            c = NewGoogleOauth2ClientTester(props)
            uri = props.GetAsString("google.client.test_url")
        case "linkedin.com":
            c = NewLinkedInOauth2ClientTester(props)
            uri = props.GetAsString("linkedin.client.test_url")
        case "smugmug.com":
            // smugmug doesn't support query strings properly
            newRawUrl := strings.Replace(req.RawURL, "site=smugmug.com?", "site=smugmug.com&", 1)
            newUrl, _ := url.Parse(newRawUrl)
            if newUrl != nil {
                req.URL = newUrl
                req.RawURL = newRawUrl
                q = newUrl.Query()
            }
            c = NewSmugMugOauth2ClientTester(props)
            uri = props.GetAsString("smugmug.client.test_url")
        case "twitter.com":
            c = NewTwitterOauth2ClientTester(props)
            uri = props.GetAsString("twitter.client.test_url")
        case "yahoo.com":
            c = NewYahooOauth2ClientTester(props)
            uri = props.GetAsString("yahoo.client.test_url")
        default:
            log.Fatal("Unable to determine OAuth2 client to handle response: ", req.URL.String())
        }
    } else {
        log.Fatal("Unable to determine OAuth2 client to handle response: ", req.URL.String())
    }
    err := c.ExchangeRequestTokenForAccess(req)
    if err != nil {
        w.Header().Set("Content-Type", "text/plain")
        w.WriteHeader(500)
        io.WriteString(w, "Error exchanging request token for access token\n\n")
        io.WriteString(w, err.String())
        return
    }
    log.Print("Retrieving User Info...")
    userInfo, err3 := c.RetrieveUserInfo()
    log.Printf("UserInfo: %T %v", userInfo, userInfo)
    log.Printf("Error: %T %v", err3, err3)
    
    r, _, err2 := oauth2_client.AuthorizedRequest(c, method, headers, uri, query, reader)
    if err2 != nil {
        w.Header().Set("Content-Type", "text/plain")
        w.WriteHeader(500)
        io.WriteString(w, "Error retrieving authorized response for " + uri + "?" + query.Encode() + "\n\n")
        io.WriteString(w, err.String())
        return
    }
    h := w.Header()
    for k, v := range r.Header {
        for _, v1 := range v {
            h.Add(k, v1)
        }
    }
    w.WriteHeader(r.StatusCode)
    io.Copy(w, r.Body)
    return
}

func getProperties() oauth2_client.JSONObject {
    props, _ := readPropertiesFile("settings.json")
    return props
}

func readPropertiesFile(filename string) (oauth2_client.JSONObject, os.Error) {
    props := oauth2_client.NewJSONObject()
    propFile, err := os.Open(filename)
    if propFile == nil {
        log.Fatal("Could not open properties file: ", filename)
        return props, err
    }
    defer propFile.Close()
    if err != nil {
        log.Fatal("Error opening file ", filename, ": ", err.String())
        return props, err
    }
    json.NewDecoder(propFile).Decode(&props)
    if err != nil {
        log.Fatal("Error reading settings: ", err)
    }
    if len(props) <= 0 {
        log.Fatal("No settings found in properties file")
    }
    return props, err
}

func main() {
    http.HandleFunc("/auth/oauth2/oauth2callback", HandleClientAccept)
    http.HandleFunc("/facebook", HandleFacebookOauthRequest)
    http.HandleFunc("/google", HandleGoogleOauthRequest)
    http.HandleFunc("/linkedin", HandleLinkedInOauthRequest)
    http.HandleFunc("/smugmug", HandleSmugMugOauthRequest)
    http.HandleFunc("/twitter", HandleTwitterOauthRequest)
    http.HandleFunc("/yahoo", HandleYahooOauthRequest)
    http.HandleFunc("/", HandlePage)
    log.Print("About to start serving on port 8000")
    err := http.ListenAndServe(":8000", nil)
    if err != nil {
        log.Fatal("ListenAndServe: ", err.String())
    }
}



