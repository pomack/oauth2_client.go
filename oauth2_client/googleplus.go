package oauth2_client

import (
    "github.com/pomack/jsonhelper.go/jsonhelper"
    "bytes"
    "http"
    "io"
    "json"
    "os"
    "strconv"
    "strings"
    "time"
    "url"
)

type GooglePlusUserInfoResult interface {
    UserInfo
    Id() string
    MiddleName() string
    Prefix() string
    Suffix() string
    Nickname() string
    EmailAddresses() []string
    Urls() []string
}

type googleplusName struct {
    FamilyName string `json:"familyName,omitempty"`
    Formatted string `json:"formatted,omitempty"`
    GivenName string `json:"givenName,omitempty"`
    HonorificPrefix string `json:"honorificPrefix,omitempty"`
    HonorificSuffix string `json:"honorificSuffix,omitempty"`
    MiddleName string `json:"middleName,omitempty"`
}

type googleplusUrl struct {
    Primary string  `json:"primary,omitempty"`
    Type    string  `json:"type,omitempty"`
    Value   string  `json:"value,omitempty"`
}

type googleplusUserInfoResult struct {
    id          string          `json:"id,omitempty"`
    displayName string          `json:"displayName,omitempty"`
    name        googleplusName  `json:"name,omitempty"`
    nickname    string          `json:"nickname,omitempty"`
    emails      []string        `json:"emails,omitempty"`
    url         string          `json:"url,omitempty"`
    urls        []googleplusUrl `json:"link,omitempty"`
}

func (p *googleplusUserInfoResult) Guid() string        { return p.id }
func (p *googleplusUserInfoResult) Username() string    { return p.id }
func (p *googleplusUserInfoResult) GivenName() string   { return p.name.GivenName }
func (p *googleplusUserInfoResult) FamilyName() string  { return p.name.FamilyName }
func (p *googleplusUserInfoResult) DisplayName() string { return p.displayName }
func (p *googleplusUserInfoResult) Url() string         { return p.url }
func (p *googleplusUserInfoResult) Id() string          { return p.id }
func (p *googleplusUserInfoResult) MiddleName() string  { return p.name.MiddleName }
func (p *googleplusUserInfoResult) Prefix() string      { return p.name.HonorificPrefix }
func (p *googleplusUserInfoResult) Suffix() string      { return p.name.HonorificSuffix }
func (p *googleplusUserInfoResult) Nickname() string    { return p.nickname }
func (p *googleplusUserInfoResult) EmailAddresses() []string { return p.emails }
func (p *googleplusUserInfoResult) Urls() []string      {
    l := len(p.urls)
    arr := make([]string, l)
    for i, theurl := range p.urls {
        arr[i] = theurl.Value
    }
    return arr
}

type googleplusClient struct {
    client       *http.Client
    clientId     string     "client_id"
    clientSecret string     "client_secret"
    redirectUri  string     "redirect_uri"
    scope        string     "scope"
    state        string     "state"
    accessToken  string     "access_token"
    expiresAt    *time.Time "expires_at"
    tokenType    string     "token_type"
    refreshToken string     "refresh_token"
}

type googleplusAuthorizationCodeResponse struct {
    AccessToken  string  `json:"access_token"`
    ExpiresIn    float64 `json:"expires_in"`
    TokenType    string  `json:"token_type"`
    RefreshToken string  `json:"refresh_token"`
}

func NewGooglePlusClient() *googleplusClient {
    return &googleplusClient{client: new(http.Client)}
}

func (p *googleplusClient) Client() *http.Client {
    return p.client
}

func (p *googleplusClient) ClientId() string      { return p.clientId }
func (p *googleplusClient) ClientSecret() string  { return p.clientSecret }
func (p *googleplusClient) RedirectUri() string   { return p.redirectUri }
func (p *googleplusClient) AccessToken() string   { return p.accessToken }
func (p *googleplusClient) ExpiresAt() *time.Time { return p.expiresAt }
func (p *googleplusClient) ExpiresAtString() string {
    if p.expiresAt == nil {
        return ""
    }
    return p.expiresAt.Format(GOOGLE_DATETIME_FORMAT)
}
func (p *googleplusClient) TokenType() string    { return p.tokenType }
func (p *googleplusClient) RefreshToken() string { return p.refreshToken }

func (p *googleplusClient) ServiceId() string { return "plus.google.com" }
func (p *googleplusClient) Initialize(properties jsonhelper.JSONObject) {
    if properties == nil || len(properties) <= 0 {
        return
    }
    if v, ok := properties["googleplus.client.id"]; ok {
        p.clientId = v.(string)
    }
    if v, ok := properties["googleplus.client.secret"]; ok {
        p.clientSecret = v.(string)
    }
    if v, ok := properties["googleplus.client.redirect_uri"]; ok {
        p.redirectUri = v.(string)
    }
    if v, ok := properties["googleplus.client.scope"]; ok {
        p.scope = v.(string)
    }
    if v, ok := properties["googleplus.client.state"]; ok {
        p.state = v.(string)
    }
    if v, ok := properties["googleplus.client.access_token"]; ok {
        p.accessToken = v.(string)
    }
    if v, ok := properties["googleplus.client.expires_at"]; ok {
        seconds, err := strconv.Atoi64(v.(string))
        if err == nil {
            p.expiresAt = time.SecondsToUTC(time.Seconds() + seconds)
        } else {
            if expiresAt, err := time.Parse(GOOGLE_DATETIME_FORMAT, v.(string)); err == nil {
                p.expiresAt = expiresAt
            }
        }
    }
    if v, ok := properties["googleplus.client.token_type"]; ok {
        p.tokenType = v.(string)
    }
    if v, ok := properties["googleplus.client.refresh_token"]; ok {
        p.refreshToken = v.(string)
    }
}

func (p *googleplusClient) Scope() string {
    return p.scope
}

func (p *googleplusClient) SetScope(scope string) {
    p.scope = scope
}

func (p *googleplusClient) State() string {
    return p.state
}

func (p *googleplusClient) SetState(state string) {
    p.state = state
}

func (p *googleplusClient) GenerateAuthorizationCodeUri(code string) (string, url.Values) {
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
    return _GOOGLEPLUS_AUTHORIZATION_CODE_URL, m
}

func (p *googleplusClient) HandleClientAccept(code string) os.Error {
    now := time.UTC()
    url, m := p.GenerateAuthorizationCodeUri(code)
    req, err := http.NewRequest(_GOOGLEPLUS_AUTHORIZATION_CODE_METHOD, url, bytes.NewBufferString(m.Encode()))
    if err != nil {
        LogError("Unable to retrieve generate authorization code uri")
        return err
    }
    req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
    r, _, err := MakeRequest(p.client, req)
    //r, err := http.PostForm(url, m)
    if err != nil {
        LogError("Unable to retrieve generate authorization code uri")
        return err
    }
    s := new(googleplusAuthorizationCodeResponse)
    err2 := json.NewDecoder(r.Body).Decode(s)
    LogDebugf("Loaded response %T -> %#v", s, s)
    if err2 != nil {
        LogError("Unable to decode the response from ", r.Body)
        return err2
    }
    if len(s.AccessToken) > 0 && len(s.RefreshToken) > 0 {
        p.expiresAt = time.SecondsToUTC(now.Seconds() + int64(s.ExpiresIn))
        p.accessToken = s.AccessToken
        p.tokenType = s.TokenType
        p.refreshToken = s.RefreshToken
    }
    return nil
}

func (p *googleplusClient) handleClientAcceptRequest(req *http.Request) os.Error {
    q := req.URL.Query()
    error := q.Get("error")
    if len(error) > 0 {
        LogError("Received error in client accept request")
        return os.NewError(error)
    }
    code := q.Get("code")
    if len(code) <= 0 {
        LogError("Received no code in client accept request")
        return os.NewError("Expected URL parameter \"code\" in request but not found")
    }
    return p.HandleClientAccept(code)
}

func (p *googleplusClient) UpdateAccessToken() (string, os.Error) {
    now := time.UTC()
    if p.expiresAt == nil || p.expiresAt.Seconds() <= now.Seconds() {
        m := make(url.Values)
        m.Add("client_id", p.clientId)
        m.Add("client_secret", p.clientSecret)
        m.Add("refresh_token", p.refreshToken)
        m.Add("grant_type", "refresh_token")
        req, err := http.NewRequest(_GOOGLEPLUS_REFRESH_TOKEN_METHOD, _GOOGLEPLUS_REFRESH_TOKEN_URL, bytes.NewBufferString(m.Encode()))
        if err != nil {
            return "", err
        }
        req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
        r, _, err := MakeRequest(p.client, req)
        //r, err := http.PostForm(uri, m)
        if err != nil {
            return "", err
        }
        s := new(googleplusAuthorizationCodeResponse)
        err2 := json.NewDecoder(r.Body).Decode(s)
        LogDebugf("Loaded response %T -> %#v", s, s)
        if err2 != nil {
            return "", err2
        }
        if len(s.AccessToken) > 0 {
            p.expiresAt = time.SecondsToUTC(now.Seconds() + int64(s.ExpiresIn))
            p.accessToken = s.AccessToken
            if len(s.RefreshToken) > 0 {
                p.refreshToken = s.RefreshToken
            }
        }
    }
    return p.accessToken, nil
}

func (p *googleplusClient) GenerateRequestTokenUrl(properties jsonhelper.JSONObject) string {
    if properties == nil {
        properties = jsonhelper.NewJSONObject()
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
    return MakeUrl(_GOOGLEPLUS_ACCESS_TOKEN_URL, m)
}

func (p *googleplusClient) RequestTokenGranted(req *http.Request) bool {
    if err := p.handleClientAcceptRequest(req); err != nil {
        LogError("Error in client accept request: ", err.String())
        return false
    }
    return true
}

func (p *googleplusClient) ExchangeRequestTokenForAccess(req *http.Request) os.Error {
    if len(p.refreshToken) <= 0 {
        if err := p.handleClientAcceptRequest(req); err != nil {
            return err
        }
    }
    _, err := p.UpdateAccessToken()
    return err
}

func (p *googleplusClient) CreateAuthorizedRequest(method string, headers http.Header, uri string, query url.Values, r io.Reader) (*http.Request, os.Error) {
    if len(method) <= 0 {
        method = GET
    }
    method = strings.ToUpper(method)
    if headers == nil {
        headers = make(http.Header)
    }
    if query == nil {
        query = make(url.Values)
    }
    accessToken, err := p.UpdateAccessToken()
    if err != nil {
        return nil, err
    }
    headers.Set("Authorization", "Bearer "+accessToken)
    fullUrl := MakeUrl(uri, query)
    req, err := http.NewRequest(method, fullUrl, r)
    if req != nil {
        req.Header = headers
    }
    return req, err
}

func (p *googleplusClient) RetrieveUserInfo() (UserInfo, os.Error) {
    req, err := p.CreateAuthorizedRequest(_GOOGLEPLUS_USERINFO_METHOD, nil, _GOOGLEPLUS_USERINFO_URL, nil, nil)
    if err != nil {
        return nil, err
    }
    result := new(googleplusUserInfoResult)
    resp, _, err := MakeRequest(p.client, req)
    if resp != nil && resp.Body != nil {
        if err2 := json.NewDecoder(resp.Body).Decode(result); err == nil {
            err = err2
        }
    }
    return result, err
}
