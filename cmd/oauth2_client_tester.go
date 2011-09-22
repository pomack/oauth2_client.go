package main

import (
    "github.com/pomack/jsonhelper"
    "github.com/pomack/oauth2_client"
    "bytes"
    "http"
    "io"
    "json"
    "log"
    "os"
    "strings"
    "template"
    "url"
)

const (
    HOMEPAGE = `<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE html>
<html>
    <head>
        <title>OAuth Test Homepage</title>
    </head>
    <body>
        <h1>OAuth Test Homepage</h1>
        <p>
            <a href="/facebook/">Test Facebook OAuth</a><br/>
            <a href="/google/">Test Google OAuth</a><br/>
            <a href="/linkedin/">Test LinkedIn OAuth</a><br/>
            <a href="/smugmug/">Test SmugMug OAuth</a><br/>
            <a href="/twitter/">Test Twitter OAuth</a><br/>
            <a href="/yahoo/">Test Yahoo! OAuth</a><br/>
        </p>
    </body>
</html>
`

    GOOGLE_TEST_PAGE = `<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE html>
<html>
    <head>
        <title>Google OAuth 2.0 Test Homepage</title>
        <style type="text/css">
            label {
                width: 10em;
                font-weight: bold;
            }
        </style>
    </head>
    <body>
        <h1>Google OAuth 2.0 Test Homepage</h1>
        <form method="POST" action="/google/test/">
        <p>
            <label for="google.client.access_token">Access Token:</label>
            <input type="text" name="google.client.access_token" value="{{.c.AccessToken|html}}" size="80"/><br/>
            
            <label for="google.client.expires_at">Expires At:</label>
            <input type="text" name="google.client.expires_at" value="{{.c.ExpiresAtString|html}}" readonly="readonly" size="80"/><br/>
            
            <label for="google.client.token_type">Token Type:</label>
            <input type="text" name="google.client.token_type" value="{{.c.TokenType|html}}" readonly="readonly" size="80"/><br/>
            
            <label for="google.client.refresh_token">Refresh Token:</label>
            <input type="text" name="google.client.refresh_token" value="{{.c.RefreshToken|html}}" size="80"/><br/>
            
            <label for="google.client.test_url">URL:</label>
            <input type="text" name="google.client.test_url" value="{{.url|html}}" size="120"/><br/>
            
            <input type="submit" name="submit" value="Submit"/>
        </p>
        </form>
        <div>
            <pre>{{.output|html}}</pre>
        </div>
    </body>
</html>
`

    FACEBOOK_TEST_PAGE = `<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE html>
<html>
    <head>
        <title>Facebook OAuth 2.0 Test Homepage</title>
        <style type="text/css">
            label {
                width: 10em;
                font-weight: bold;
            }
        </style>
    </head>
    <body>
        <h1>Facebook OAuth 2.0 Test Homepage</h1>
        <form method="POST" action="/facebook/test/">
        <p>
            <label for="facebook.client.access_token">Access Token:</label>
            <input type="text" name="facebook.client.access_token" value="{{.c.AccessToken|html}}" size="160"/><br/>
            
            <label for="facebook.client.expires_at">Expires At:</label>
            <input type="text" name="facebook.client.expires_at" value="{{.c.ExpiresAtString|html}}" readonly="readonly" size="40"/><br/>
            
            <label for="facebook.client.test_url">URL:</label>
            <input type="text" name="facebook.client.test_url" value="{{.url|html}}" size="120"/><br/>
            
            <input type="submit" name="submit" value="Submit"/>
        </p>
        </form>
        <div>
            <pre>{{.output|html}}</pre>
        </div>
    </body>
</html>
`

    LINKEDIN_TEST_PAGE = `<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE html>
<html>
    <head>
        <title>LinkedIn OAuth 1.0 Test Homepage</title>
        <style type="text/css">
            label {
                width: 10em;
                font-weight: bold;
            }
        </style>
    </head>
    <body>
        <h1>LinkedIn OAuth 1.0 Test Homepage</h1>
        <form method="POST" action="/linkedin/test/">
        <p>
            <label for="linkedin.client.token">Token:</label>
            <input type="text" name="linkedin.client.token" value="{{.c.CurrentCredentials.Token|html}}" size="80"/><br/>
            
            <label for="linkedin.client.secret">Secret:</label>
            <input type="text" name="linkedin.client.secret" value="{{.c.CurrentCredentials.Secret|html}}" readonly="readonly" size="80"/><br/>
            
            <label for="linkedin.client.test_url">URL:</label>
            <input type="text" name="linkedin.client.test_url" value="{{.url|html}}" size="120"/><br/>
            
            <input type="submit" name="submit" value="Submit"/>
        </p>
        </form>
        <div>
            <pre>{{.output|html}}</pre>
        </div>
    </body>
</html>
`

    SMUGMUG_TEST_PAGE = `<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE html>
<html>
    <head>
        <title>SmugMug OAuth 1.0 Test Homepage</title>
        <style type="text/css">
            label {
                width: 10em;
                font-weight: bold;
            }
        </style>
    </head>
    <body>
        <h1>SmugMug OAuth 1.0 Test Homepage</h1>
        <form method="POST" action="/smugmug/test/">
        <p>
            <label for="smugmug.client.token">Token:</label>
            <input type="text" name="smugmug.client.token" value="{{.c.CurrentCredentials.Token|html}}" size="80"/><br/>
            
            <label for="smugmug.client.secret">Secret:</label>
            <input type="text" name="smugmug.client.secret" value="{{.c.CurrentCredentials.Secret|html}}" readonly="readonly" size="80"/><br/>
            
            <label for="smugmug.client.test_url">URL:</label>
            <input type="text" name="smugmug.client.test_url" value="{{.url|html}}" size="120"/><br/>
            
            <input type="submit" name="submit" value="Submit"/>
        </p>
        </form>
        <div>
            <pre>{{.output|html}}</pre>
        </div>
    </body>
</html>
`

    TWITTER_TEST_PAGE = `<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE html>
<html>
    <head>
        <title>Twitter OAuth 1.0 Test Homepage</title>
        <style type="text/css">
            label {
                width: 10em;
                font-weight: bold;
            }
        </style>
    </head>
    <body>
        <h1>Twitter OAuth 1.0 Test Homepage</h1>
        <form method="POST" action="/twitter/test/">
        <p>
            <label for="twitter.client.token">Token:</label>
            <input type="text" name="twitter.client.token" value="{{.c.CurrentCredentials.Token|html}}" size="80"/><br/>
            
            <label for="twitter.client.secret">Secret:</label>
            <input type="text" name="twitter.client.secret" value="{{.c.CurrentCredentials.Secret|html}}" readonly="readonly" size="80"/><br/>
            
            <label for="twitter.client.test_url">URL:</label>
            <input type="text" name="twitter.client.test_url" value="{{.url|html}}" size="120"/><br/>
            
            <input type="submit" name="submit" value="Submit"/>
        </p>
        </form>
        <div>
            <pre>{{.output|html}}</pre>
        </div>
    </body>
</html>
`

    YAHOO_TEST_PAGE = `<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE html>
<html>
    <head>
        <title>Yahoo! OAuth 1.0 Test Homepage</title>
        <style type="text/css">
            label {
                width: 10em;
                font-weight: bold;
            }
        </style>
    </head>
    <body>
        <h1>Yahoo! OAuth 1.0 Test Homepage</h1>
        <form method="POST" action="/yahoo/test/">
        <p>
            <label for="yahoo.client.token">Token:</label>
            <input type="text" name="yahoo.client.token" value="{{.c.CurrentCredentials.Token|html}}" size="80"/><br/>
            
            <label for="yahoo.client.secret">Secret:</label>
            <input type="text" name="yahoo.client.secret" value="{{.c.CurrentCredentials.Secret|html}}" readonly="readonly" size="80"/><br/>
            
            <label for="yahoo.client.test_url">URL:</label>
            <input type="text" name="yahoo.client.test_url" value="{{.url|html}}" size="120"/><br/>
            
            <input type="submit" name="submit" value="Submit"/>
        </p>
        </form>
        <div>
            <pre>{{.output|html}}</pre>
        </div>
    </body>
</html>
`

)

var (
    PARSED_GOOGLE_TEMPLATE *template.Template
    PARSED_FACEBOOK_TEMPLATE *template.Template
    PARSED_LINKEDIN_TEMPLATE *template.Template
    PARSED_SMUGMUG_TEMPLATE *template.Template
    PARSED_TWITTER_TEMPLATE *template.Template
    PARSED_YAHOO_TEMPLATE *template.Template
)

func HandlePage(w http.ResponseWriter, req *http.Request) {
    w.Header().Set("Content-Type", "text/html")
    w.WriteHeader(200)
    io.WriteString(w, HOMEPAGE)
}

func HandleGenericOauthRequest(c oauth2_client.OAuth2Client, w http.ResponseWriter, req *http.Request) {
    uri := c.GenerateRequestTokenUrl(jsonhelper.NewJSONObject())
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
    oauth2_client.LogInfo("=================================")
    oauth2_client.LogInfo("Received request from User: ")
    reqBytes, _ := http.DumpRequest(req, true)
    oauth2_client.LogInfo(string(reqBytes))
    oauth2_client.LogInfo("=================================")
    var useTemplate *template.Template = nil
    var useTemplateData interface{} = nil
    if site := q.Get("site"); len(site) > 0 {
        if index := strings.Index(site, "?"); index >= 0 {
            site = site[0:index]
        }
        m := make(map[string]interface{})
        switch site {
        case "facebook.com":
            c = NewFacebookOauth2ClientTester(props)
            uri = props.GetAsString("facebook.client.test_url")
            useTemplate = PARSED_FACEBOOK_TEMPLATE
        case "google.com":
            c = NewGoogleOauth2ClientTester(props)
            uri = props.GetAsString("google.client.test_url")
            useTemplate = PARSED_GOOGLE_TEMPLATE
        case "linkedin.com":
            c = NewLinkedInOauth2ClientTester(props)
            uri = props.GetAsString("linkedin.client.test_url")
            useTemplate = PARSED_LINKEDIN_TEMPLATE
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
            useTemplate = PARSED_SMUGMUG_TEMPLATE
        case "twitter.com":
            c = NewTwitterOauth2ClientTester(props)
            uri = props.GetAsString("twitter.client.test_url")
            useTemplate = PARSED_TWITTER_TEMPLATE
        case "yahoo.com":
            c = NewYahooOauth2ClientTester(props)
            uri = props.GetAsString("yahoo.client.test_url")
            useTemplate = PARSED_YAHOO_TEMPLATE
        default:
            log.Fatal("Unable to determine OAuth client to handle response: ", req.URL.String())
        }
        m["c"] = c
        m["url"] = uri
        m["output"] = ""
        useTemplateData = m
    } else {
        log.Fatal("Unable to determine OAuth client to handle response: ", req.URL.String())
    }
    err := c.ExchangeRequestTokenForAccess(req)
    if err != nil {
        w.Header().Set("Content-Type", "text/plain")
        w.WriteHeader(500)
        io.WriteString(w, "Error exchanging request token for access token\n\n")
        io.WriteString(w, err.String())
        return
    }
    if useTemplate != nil {
        w.Header().Set("Content-Type", "text/html")
        w.WriteHeader(200)
        err = useTemplate.Execute(w, useTemplateData)
        if err != nil {
            oauth2_client.LogErrorf("Error: %T %v", err, err)
        }
    } else {
        oauth2_client.LogInfo("Retrieving User Info...")
        userInfo, err3 := c.RetrieveUserInfo()
        oauth2_client.LogInfof("UserInfo: %T %v", userInfo, userInfo)
        oauth2_client.LogInfof("Error: %T %v", err3, err3)
    
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
}

func HandleGenericOauthTestRequest(w http.ResponseWriter, req *http.Request, c oauth2_client.OAuth2Client, method, test_url_property, body string, useTemplate *template.Template) {
    props := getProperties()
    if req.Method == oauth2_client.POST {
        if err := req.ParseForm(); err != nil {
            w.Header().Set("Content-Type", "text/plain")
            w.WriteHeader(500)
            io.WriteString(w, "Unable to parse form:\n\n")
            io.WriteString(w, err.String())
            return
        }
        for k, arr := range req.Form {
            for _, v := range arr {
                props.Set(k, v)
            }
        }
    }
    for k, arr := range req.URL.Query() {
        for _, v := range arr {
            props.Set(k, v)
        }
    }
    c.Initialize(props)
    uri := props.GetAsString(test_url_property)
    log.Printf("Client is: %T -> %#v", c, c)
    var reader io.Reader = nil
    if len(body) > 0 {
        reader = bytes.NewBufferString(body)
    }
    resp, _, err := oauth2_client.AuthorizedRequest(c, method, nil, uri, nil, reader)
    m := make(map[string]interface{})
    isError := false
    m["c"] = c
    m["url"] = uri
    if err != nil {
        m["output"] = err.String()
        isError = true
    } else {
        b, err := http.DumpResponse(resp, true)
        if err != nil {
            m["output"] = err.String()
            isError = true
        } else {
            m["output"] = string(b)
        }
    }
    if isError {
        w.Header().Set("Content-Type", "text/plain")
        w.WriteHeader(500)
    } else {
        w.Header().Set("Content-Type", "text/html")
        w.WriteHeader(200)
    }
    err = useTemplate.Execute(w, m)
    if err != nil {
        oauth2_client.LogErrorf("Error: %T %v", err, err)
    }
}


func HandleGoogleOauthTestRequest(w http.ResponseWriter, req *http.Request) {
    HandleGenericOauthTestRequest(w, req, oauth2_client.NewGoogleClient(), oauth2_client.GET, "google.client.test_url", "", PARSED_GOOGLE_TEMPLATE)
}

func HandleFacebookOauthTestRequest(w http.ResponseWriter, req *http.Request) {
    HandleGenericOauthTestRequest(w, req, oauth2_client.NewFacebookClient(), oauth2_client.GET, "facebook.client.test_url", "", PARSED_FACEBOOK_TEMPLATE)
}

func HandleLinkedInOauthTestRequest(w http.ResponseWriter, req *http.Request) {
    HandleGenericOauthTestRequest(w, req, oauth2_client.NewLinkedInClient(), oauth2_client.GET, "linkedin.client.test_url", "", PARSED_LINKEDIN_TEMPLATE)
}

func HandleSmugMugOauthTestRequest(w http.ResponseWriter, req *http.Request) {
    HandleGenericOauthTestRequest(w, req, oauth2_client.NewSmugMugClient(), oauth2_client.GET, "smugmug.client.test_url", "", PARSED_SMUGMUG_TEMPLATE)
}

func HandleTwitterOauthTestRequest(w http.ResponseWriter, req *http.Request) {
    HandleGenericOauthTestRequest(w, req, oauth2_client.NewTwitterClient(), oauth2_client.GET, "twitter.client.test_url", "", PARSED_TWITTER_TEMPLATE)
}

func HandleYahooOauthTestRequest(w http.ResponseWriter, req *http.Request) {
    HandleGenericOauthTestRequest(w, req, oauth2_client.NewYahooClient(), oauth2_client.GET, "yahoo.client.test_url", "", PARSED_YAHOO_TEMPLATE)
}


func getProperties() jsonhelper.JSONObject {
    props, _ := readPropertiesFile("settings.json")
    return props
}

func readPropertiesFile(filename string) (jsonhelper.JSONObject, os.Error) {
    props := jsonhelper.NewJSONObject()
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
	oauth2_client.EnableLogHttpRequests   = true
	oauth2_client.EnableLogHttpResponses  = true
	oauth2_client.EnableLogDebug          = true
	oauth2_client.EnableLogInfo           = true
	oauth2_client.EnableLogError          = true
	PARSED_GOOGLE_TEMPLATE = template.Must(template.New("google").Parse(GOOGLE_TEST_PAGE))
	PARSED_FACEBOOK_TEMPLATE = template.Must(template.New("facebook").Parse(FACEBOOK_TEST_PAGE))
	PARSED_LINKEDIN_TEMPLATE = template.Must(template.New("linkedin").Parse(LINKEDIN_TEST_PAGE))
	PARSED_SMUGMUG_TEMPLATE = template.Must(template.New("smugmug").Parse(SMUGMUG_TEST_PAGE))
	PARSED_TWITTER_TEMPLATE = template.Must(template.New("twitter").Parse(TWITTER_TEST_PAGE))
	PARSED_YAHOO_TEMPLATE = template.Must(template.New("yahoo").Parse(YAHOO_TEST_PAGE))
    http.HandleFunc("/auth/oauth2/oauth2callback/", HandleClientAccept)
    http.HandleFunc("/auth/oauth2/oauth2callback", HandleClientAccept)
    http.HandleFunc("/facebook/", HandleFacebookOauthRequest)
    http.HandleFunc("/google/", HandleGoogleOauthRequest)
    http.HandleFunc("/linkedin/", HandleLinkedInOauthRequest)
    http.HandleFunc("/smugmug/", HandleSmugMugOauthRequest)
    http.HandleFunc("/twitter/", HandleTwitterOauthRequest)
    http.HandleFunc("/yahoo/", HandleYahooOauthRequest)
    http.HandleFunc("/google/test/", HandleGoogleOauthTestRequest)
    http.HandleFunc("/facebook/test/", HandleFacebookOauthTestRequest)
    http.HandleFunc("/linkedin/test/", HandleLinkedInOauthTestRequest)
    http.HandleFunc("/smugmug/test/", HandleSmugMugOauthTestRequest)
    http.HandleFunc("/twitter/test/", HandleTwitterOauthTestRequest)
    http.HandleFunc("/yahoo/test/", HandleYahooOauthTestRequest)
    http.HandleFunc("/", HandlePage)
    log.Print("About to start serving on port 8000")
    err := http.ListenAndServe(":8000", nil)
    if err != nil {
        log.Fatal("ListenAndServe: ", err.String())
    }
}



