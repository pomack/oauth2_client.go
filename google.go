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

type GoogleUserInfoResult interface {
    UserInfo
    Id()                string
    Name()              string
    FirstName()         string
    LastName()          string
    Link()              string
    Hometown()          FacebookLocation
    Location()          FacebookLocation
    Gender()            string
    Email()             string
    Timezone()          float64
    Locale()            string
    Verified()          bool
    UpdatedTime()       *time.Time
}

type googleUserInfoResult struct {
    id                  string              `json:"id"`
    name                string              `json:"name"`
    email               string              `json:"email"`
    uri                 string              `json:"link"`
    updated             *time.Time          `json:"updated"`
}

func (p *googleUserInfoResult) Guid() string { return p.id }
func (p *googleUserInfoResult) Username() string { return p.id }
func (p *googleUserInfoResult) GivenName() string { return p.name }
func (p *googleUserInfoResult) FamilyName() string { return p.name }
func (p *googleUserInfoResult) DisplayName() string { return p.name }
func (p *googleUserInfoResult) Url() string { return p.uri }
func (p *googleUserInfoResult) Id() string { return p.id }
func (p *googleUserInfoResult) Name() string { return p.name }
func (p *googleUserInfoResult) Updated() *time.Time { return p.updated }
func (p *googleUserInfoResult) UnmarshalJSON(data []byte) os.Error {
    props := NewJSONObject()
    err := json.Unmarshal(data, &props)
    p.FromJSON(props)
    return err
}
func (p *googleUserInfoResult) FromJSON(props JSONObject) {
    p.id = props.GetAsObject("id").GetAsString("$t")
    authorArr := props.GetAsArray("author")
    if len(authorArr) > 0 {
        author := JSONValueToObject(authorArr[0])
        p.name = author.GetAsObject("name").GetAsString("$t")
        p.email = author.GetAsObject("email").GetAsString("$t")
    }
    for _, l := range props.GetAsArray("link") {
        m := JSONValueToObject(l)
        if m.GetAsString("rel") == _GOOGLE_USERINFO_FEED_REL {
            p.uri = m.GetAsString("href")
        }
    }
    p.updated = props.GetAsObject("updated").GetAsTime("$t", GOOGLE_DATETIME_FORMAT)
}

type googleClient struct {
    client                      *http.Client
    clientId                    string "client_id"
    clientSecret                string "client_secret"
    redirectUri                 string "redirect_uri"
    scope                       string "scope"
    state                       string "state"
    accessToken                 string "access_token"
    expiresAt                   *time.Time "expires_at"
    tokenType                   string "token_type"
    refreshToken                string "refresh_token"
}

type googleAuthorizationCodeResponse struct {
    AccessToken     string  `json:"access_token"`
    ExpiresIn       float64 `json:"expires_in"`
    TokenType       string  `json:"token_type"`
    RefreshToken    string  `json:"refresh_token"`
}

func NewGoogleClient() *googleClient {
    return &googleClient{client:new(http.Client)}
}

func (p *googleClient) Client() *http.Client {
    return p.client
}

func (p *googleClient) ServiceId() string { return "google.com" }
func (p *googleClient) Initialize(properties JSONObject) {
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

func (p *googleClient) Scope() string {
    return p.scope
}

func (p *googleClient) SetScope(scope string) {
    p.scope = scope
}

func (p *googleClient) State() string {
    return p.state
}

func (p *googleClient) SetState(state string) {
    p.state = state
}

func (p *googleClient) GenerateAuthorizationCodeUri(code string) (string, url.Values) {
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
    return _GOOGLE_AUTHORIZATION_CODE_URL, m
}

func (p *googleClient) handleClientAccept(code string) os.Error {
    now := time.UTC()
    url, m := p.GenerateAuthorizationCodeUri(code)
    req, err := http.NewRequest(_GOOGLE_AUTHORIZATION_CODE_METHOD, url, bytes.NewBufferString(m.Encode()))
    if err != nil {
        log.Print("Unable to retrieve generate authorization code uri")
        return err
    }
    req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
    r, _, err := makeRequest(p.client, req)
    //r, err := http.PostForm(url, m)
    if err != nil {
        log.Print("Unable to retrieve generate authorization code uri")
        return err
    }
    var s googleAuthorizationCodeResponse
    err2 := json.NewDecoder(r.Body).Decode(&s)
    log.Printf("Loaded response %T -> %v", s, s)
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

func (p *googleClient) handleClientAcceptRequest(req *http.Request) os.Error {
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
    return p.handleClientAccept(code)
}

func (p *googleClient) AccessToken() (string, os.Error) {
    now := time.UTC()
    if p.expiresAt == nil || p.expiresAt.Seconds() <= now.Seconds() {
        m := make(url.Values)
        m.Add("client_id", p.clientId)
        m.Add("client_secret", p.clientSecret)
        m.Add("refresh_token", p.refreshToken)
        m.Add("grant_type", "refresh_token")
        req, err := http.NewRequest(_GOOGLE_REFRESH_TOKEN_METHOD, _GOOGLE_REFRESH_TOKEN_URL, bytes.NewBufferString(m.Encode()))
        if err != nil {
            return "", err
        }
        req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
        r, _, err := makeRequest(p.client, req)
        //r, err := http.PostForm(uri, m)
        if err != nil {
            return "", err
        }
        var s googleAuthorizationCodeResponse
        err2 := json.NewDecoder(r.Body).Decode(&s)
        log.Printf("Loaded response %T -> %v", s, s)
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

func (p *googleClient) GenerateRequestTokenUrl(properties JSONObject) string {
    if properties == nil {
        properties = NewJSONObject()
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
    return makeUrl(_GOOGLE_ACCESS_TOKEN_URL, m)
}

func (p *googleClient) RequestTokenGranted(req *http.Request) bool {
    if err := p.handleClientAcceptRequest(req); err != nil {
        log.Print("Error in client accept request: ", err.String())
        return false
    }
    return true
}

func (p *googleClient) ExchangeRequestTokenForAccess(req *http.Request) os.Error {
    if len(p.refreshToken) <= 0 {
        if err := p.handleClientAcceptRequest(req); err != nil {
            return err
        }
    }
    _, err := p.AccessToken()
    return err
}

func (p *googleClient) CreateAuthorizedRequest(method string, headers http.Header, uri string, query url.Values, r io.Reader) (*http.Request, os.Error) {
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
    headers.Set("Authorization", "Bearer " + accessToken)
    fullUrl := makeUrl(uri, query)
    req, err := http.NewRequest(method, fullUrl, r)
    if req != nil {
        req.Header = headers
    }
    return req, err
}

func (p *googleClient) RetrieveUserInfo() (UserInfo, os.Error) {
    req, err := p.CreateAuthorizedRequest(_GOOGLE_USERINFO_METHOD, nil, _GOOGLE_USERINFO_URL, nil, nil)
    if err != nil {
        return nil, err
    }
    result := new(googleUserInfoResult)
    resp, _, err := makeRequest(p.client, req)
    if resp != nil && resp.Body != nil {
        props := NewJSONObject()
        if err2 := json.NewDecoder(resp.Body).Decode(&props); err == nil {
            err = err2
        }
        result.FromJSON(props.GetAsObject("feed"))
    }
    return result, err
}

