package oauth2_client

import (
    "bytes"
    "http"
    "io"
    "json"
    "log"
    "os"
    "strconv"
    "strings"
    "time"
    "url"
)

const (
    GOOGLE_SCOPE_FEEDS = "https://www.google.com/m8/feeds/"
)

type GoogleClient struct {
    clientId        string "client_id"
    clientSecret    string "client_secret"
    redirectUri     string "redirect_uri"
    scope           string "scope"
    state           string "state"
    accessToken     string "access_token"
    expiresAt       *time.Time "expires_at"
    tokenType       string "token_type"
    refreshToken    string "refresh_token"
}

type googleAuthorizationCodeResponse struct {
    AccessToken     string  `json:"access_token"`
    ExpiresIn       float64 `json:"expires_in"`
    TokenType       string  `json:"token_type"`
    RefreshToken    string  `json:"refresh_token"`
}

func NewGoogleClient() *GoogleClient {
    return &GoogleClient{}
}

func (p *GoogleClient) Initialize(properties Properties) {
    if properties == nil || len(properties) <= 0 {
        return
    }
    if v, ok := properties["google.client.id"]; ok {
        p.clientId = v.(string)
    }
    if v, ok := properties["google.client.secret"]; ok {
        p.clientSecret = v.(string)
    }
    if v, ok := properties["google.client.redirect_uri"]; ok {
        p.redirectUri = v.(string)
    }
    if v, ok := properties["google.client.scope"]; ok {
        p.scope = v.(string)
    }
    if v, ok := properties["google.client.state"]; ok {
        p.state = v.(string)
    }
    if v, ok := properties["google.client.access_token"]; ok {
        p.accessToken = v.(string)
    }
    if v, ok := properties["google.client.expires_at"]; ok {
        seconds, _ := strconv.Atoi64(v.(string))
        p.expiresAt = time.SecondsToUTC(time.Seconds() + seconds)
    }
    if v, ok := properties["google.client.token_type"]; ok {
        p.tokenType = v.(string)
    }
    if v, ok := properties["google.client.refresh_token"]; ok {
        p.refreshToken = v.(string)
    }
}

func (p *GoogleClient) Scope() string {
    return p.scope
}

func (p *GoogleClient) SetScope(scope string) {
    p.scope = scope
}

func (p *GoogleClient) State() string {
    return p.state
}

func (p *GoogleClient) SetState(state string) {
    p.state = state
}

/*
func (p *GoogleClient) GenerateRetrieveAccessTokenUri() string {
    m := make(url.Values)
    m.Add("response_type", "code")
    m.Add("client_id", p.clientId)
    if len(p.redirectUri) > 0 {
        m.Add("redirect_uri", p.redirectUri)
    }
    if len(p.scope) > 0 {
        m.Add("scope", p.scope)
    }
    if len(p.state) > 0 {
        m.Add("state", p.state)
    }
    return "https://accounts.google.com/o/oauth2/auth?" + m.Encode()
}
*/

func (p *GoogleClient) GenerateAuthorizationCodeUri(code string) (string, url.Values) {
    m := make(url.Values)
    m.Add("grant_type", "authorization_code")
    m.Add("client_id", p.clientId)
    m.Add("client_secret", p.clientSecret)
    m.Add("code", code)
    if len(p.redirectUri) > 0 {
        m.Add("redirect_uri", p.redirectUri)
    }
    if len(p.scope) > 0 {
        m.Add("scope", p.scope)
    }
    if len(p.state) > 0 {
        m.Add("state", p.state)
    }
    return "https://accounts.google.com/o/oauth2/token?", m
}

func (p *GoogleClient) HandleClientAccept(code string) os.Error {
    now := time.UTC()
    url, m := p.GenerateAuthorizationCodeUri(code)
    req, err := http.NewRequest("POST", url, bytes.NewBufferString(m.Encode()))
    if err != nil {
        log.Print("Unable to retrieve generate authorization code uri")
        return err
    }
    req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
    r, err := MakeRequest(req)
    //r, err := http.PostForm(url, m)
    if err != nil {
        log.Print("Unable to retrieve generate authorization code uri")
        return err
    }
    decoder := json.NewDecoder(r.Body)
    var s googleAuthorizationCodeResponse
    err2 := decoder.Decode(&s)
    if err2 != nil {
        log.Print("Unable to decode the response from ", r.Body)
        return err2
    }
    if len(s.AccessToken) > 0 && len(s.RefreshToken) > 0 {
        p.expiresAt = time.SecondsToUTC(now.Seconds() + int64(s.ExpiresIn))
        p.accessToken = s.AccessToken
        p.refreshToken = s.RefreshToken
    }
    return nil
}

func (p *GoogleClient) HandleClientAcceptRequest(req *http.Request) os.Error {
    q := req.URL.Query()
    error := q.Get("error")
    if len(error) > 0 {
        log.Print("Received error in client accept request")
        return os.NewError(error)
    }
    code := q.Get("code")
    if len(code) <= 0 {
        log.Print("Received no code in client accept request")
        return os.NewError("Expected URL parameter \"code\" in request but not found")
    }
    return p.HandleClientAccept(code)
}

func (p *GoogleClient) AccessToken() (string, os.Error) {
    now := time.UTC()
    if p.expiresAt == nil || p.expiresAt.Seconds() <= now.Seconds() {
        m := make(url.Values)
        m.Add("client_id", p.clientId)
        m.Add("client_secret", p.clientSecret)
        m.Add("refresh_token", p.refreshToken)
        m.Add("grant_type", "refresh_token")
        uri := "https://accounts.google.com/o/oauth2/token"
        req, err := http.NewRequest("POST", uri, bytes.NewBufferString(m.Encode()))
        if err != nil {
            return "", err
        }
        req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
        r, err := MakeRequest(req)
        //r, err := http.PostForm(uri, m)
        if err != nil {
            return "", err
        }
        decoder := json.NewDecoder(r.Body)
        var s googleAuthorizationCodeResponse
        err2 := decoder.Decode(&s)
        if err2 != nil {
            return "", err2
        }
        if len(s.AccessToken) > 0 && len(s.RefreshToken) > 0 {
            p.expiresAt = time.SecondsToUTC(now.Seconds() + int64(s.ExpiresIn))
            p.accessToken = s.AccessToken
            p.refreshToken = s.RefreshToken
        }
    }
    return p.accessToken, nil
}

func (p *GoogleClient) GenerateRequestTokenUrl(properties Properties) string {
    if properties == nil {
        properties = make(Properties)
    }
    m := make(url.Values)
    m.Add("response_type", "code")
    if v, ok := properties["client_id"]; ok && len(v.(string)) > 0 {
        m.Add("client_id", v.(string))
    } else {
        m.Add("client_id", p.clientId)
    }
    if v, ok := properties["redirect_uri"]; ok {
        if len(v.(string)) > 0 {
            m.Add("redirect_uri", v.(string))
        }
    } else if len(p.redirectUri) > 0 {
        m.Add("redirect_uri", p.redirectUri)
    }
    if v, ok := properties["scope"]; ok {
        if len(v.(string)) > 0 {
            m.Add("scope", v.(string))
        }
    } else if len(p.scope) > 0 {
        m.Add("scope", p.scope)
    }
    if v, ok := properties["state"]; ok {
        if len(v.(string)) > 0 {
            m.Add("state", v.(string))
        }
    } else if len(p.state) > 0 {
        m.Add("state", p.state)
    }
    return "https://accounts.google.com/o/oauth2/auth?" + m.Encode()
}

func (p *GoogleClient) RequestTokenGranted(req *http.Request) bool {
    if err := p.HandleClientAcceptRequest(req); err != nil {
        log.Print("Error in client accept request: ", err.String())
        return false
    }
    return true
}

func (p *GoogleClient) ExchangeRequestTokenForAccess(req *http.Request) os.Error {
    if len(p.refreshToken) <= 0 {
        if err := p.HandleClientAcceptRequest(req); err != nil {
            return err
        }
    }
    _, err := p.AccessToken()
    return err
}

func (p *GoogleClient) CreateAuthorizedRequest(method string, headers http.Header, uri string, query url.Values, r io.Reader) (*http.Request, os.Error) {
    if len(method) <= 0 {
        method = "GET"
    }
    method = strings.ToUpper(method)
    if headers == nil {
        headers = make(http.Header)
    }
    if query == nil {
        query = make(url.Values)
    }
    accessToken, err := p.AccessToken()
    if err != nil {
        return nil, err
    }
    query.Set("access_token", accessToken)
    fullUrl := uri
    if len(query) > 0 {
        fullUrl += "?" + query.Encode()
    }
    return http.NewRequest(method, fullUrl, r)
}


func (p *GoogleClient) OAuth2Client() OAuth2Client {
    return p
}


