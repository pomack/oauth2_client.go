package oauth2_client

import (
    "github.com/pomack/jsonhelper"
    "http"
    "io"
    "json"
    "os"
    "strconv"
    "strings"
    "time"
    "url"
)

type LinkedInRequestTokenResult interface {
    AuthToken
    RequestAuthUrl() string
    ExpiresAt() *time.Time
    CallbackConfirmed() bool
}

type LinkedInAccessTokenResult interface {
    AuthToken
    ExpiresAt() *time.Time
}

type linkedInRequestTokenResult struct {
    stdAuthToken
    requestAuthUrl    string
    expiresAt         *time.Time
    callbackConfirmed bool
}

func (p *linkedInRequestTokenResult) RequestAuthUrl() string  { return p.requestAuthUrl }
func (p *linkedInRequestTokenResult) ExpiresAt() *time.Time   { return p.expiresAt }
func (p *linkedInRequestTokenResult) CallbackConfirmed() bool { return p.callbackConfirmed }

type linkedInAccessTokenResult struct {
    stdAuthToken
    expiresAt *time.Time
}

func (p *linkedInAccessTokenResult) ExpiresAt() *time.Time { return p.expiresAt }

type linkedInUserInfoResult struct {
    id               string
    firstName        string
    lastName         string
    publicProfileUrl string
}

func (p *linkedInUserInfoResult) Guid() string { return p.id }
func (p *linkedInUserInfoResult) Username() string {
    parts := strings.Split(p.publicProfileUrl, "/")
    return parts[len(parts)-1]
}
func (p *linkedInUserInfoResult) GivenName() string  { return p.firstName }
func (p *linkedInUserInfoResult) FamilyName() string { return p.lastName }
func (p *linkedInUserInfoResult) DisplayName() string {
    if len(p.firstName) > 0 && len(p.lastName) > 0 {
        return p.firstName + " " + p.lastName
    }
    return p.firstName + p.lastName
}
func (p *linkedInUserInfoResult) Url() string              { return p.publicProfileUrl }
func (p *linkedInUserInfoResult) Id() string               { return p.id }
func (p *linkedInUserInfoResult) FirstName() string        { return p.firstName }
func (p *linkedInUserInfoResult) LastName() string         { return p.lastName }
func (p *linkedInUserInfoResult) PublicProfileUrl() string { return p.publicProfileUrl }
func (p *linkedInUserInfoResult) FromJSON(props jsonhelper.JSONObject) {
    p.id = props.GetAsString("id")
    p.firstName = props.GetAsString("firstName")
    p.lastName = props.GetAsString("lastName")
    p.publicProfileUrl = props.GetAsString("publicProfileUrl")
}

type linkedInClient struct {
    stdOAuth1Client
}

func NewLinkedInClient() OAuth2Client {
    return &linkedInClient{}
}

func (p *linkedInClient) RequestUrl() string        { return _LINKEDIN_REQUEST_TOKEN_URL }
func (p *linkedInClient) RequestUrlMethod() string  { return _LINKEDIN_REQUEST_TOKEN_METHOD }
func (p *linkedInClient) RequestUrlProtected() bool { return _LINKEDIN_REQUEST_TOKEN_PROTECTED }
func (p *linkedInClient) AccessUrl() string         { return _LINKEDIN_ACCESS_TOKEN_URL }
func (p *linkedInClient) AccessUrlMethod() string   { return _LINKEDIN_ACCESS_TOKEN_METHOD }
func (p *linkedInClient) AccessUrlProtected() bool  { return _LINKEDIN_ACCESS_TOKEN_PROTECTED }
func (p *linkedInClient) AuthorizationUrl() string  { return _LINKEDIN_AUTHORIZATION_PATH_URL }
func (p *linkedInClient) AuthorizedResourceProtected() bool {
    return _LINKEDIN_AUTHORIZED_RESOURCE_PROTECTED
}
func (p *linkedInClient) ServiceId() string { return "linkedin.com" }
func (p *linkedInClient) Initialize(properties jsonhelper.JSONObject) {
    if p.currentCredentials == nil {
        p.currentCredentials = NewStandardAuthToken()
    }
    if properties == nil {
        return
    }
    if v := properties.GetAsString("linkedin.api.key"); len(v) > 0 {
        p.consumerKey = v
        //p.Credentials.Token = v
    }
    if v := properties.GetAsString("linkedin.client.redirect_uri"); len(v) > 0 {
        p.callbackUrl = v
    }
    if v := properties.GetAsString("linkedin.secret.key"); len(v) > 0 {
        p.consumerSecret = v
        //p.Credentials.Secret = v
    }
    if v := properties.GetAsString("linkedin.oauth1.scope"); len(v) > 0 {
        //p.Scope = v
    }
    if v := properties.GetAsString("linkedin.client.token"); len(v) > 0 {
        p.currentCredentials.SetToken(v)
    }
    if v := properties.GetAsString("linkedin.client.secret"); len(v) > 0 {
        p.currentCredentials.SetSecret(v)
    }
}

func (p *linkedInClient) GenerateRequestTokenUrl(properties jsonhelper.JSONObject) string {
    return oauth1GenerateRequestTokenUrl(p, properties)
}

func (p *linkedInClient) RequestTokenGranted(req *http.Request) bool {
    return oauth1RequestTokenGranted(p, req)
}

func (p *linkedInClient) ExchangeRequestTokenForAccess(req *http.Request) os.Error {
    return oauth1ExchangeRequestTokenForAccess(p, req)
}

func (p *linkedInClient) CreateAuthorizedRequest(method string, headers http.Header, uri string, query url.Values, r io.Reader) (*http.Request, os.Error) {
    if headers == nil {
        headers = make(http.Header)
    }
    headers.Set("X-Li-Format", "json")
    return oauth1CreateAuthorizedRequest(p, method, headers, uri, query, r)
}

func (p *linkedInClient) ParseRequestTokenResult(value string) (AuthToken, os.Error) {
    LogDebug("+++++++++++++++++++++++++++++++")
    LogDebug("LinkedIn Client parsing request token result")
    t := new(linkedInRequestTokenResult)
    m, err := url.ParseQuery(value)
    if m != nil {
        t.token = m.Get("oauth_token")
        t.secret = m.Get("oauth_token_secret")
        t.requestAuthUrl = m.Get("xoauth_request_auth_url")
        t.callbackConfirmed = m.Get("callback_confirmed") == "true"
        strExpiresIn := m.Get("oauth_expires_in")
        expiresIn, _ := strconv.Atoi64(strExpiresIn)
        if expiresIn > 0 {
            t.expiresAt = time.SecondsToUTC(time.Seconds() + expiresIn)
        }
        if err == nil && len(m.Get("oauth_problem")) > 0 {
            err = os.NewError(m.Get("oauth_problem"))
        }
    }
    LogDebug("+++++++++++++++++++++++++++++++")
    return t, err
}

func (p *linkedInClient) ParseAccessTokenResult(value string) (AuthToken, os.Error) {
    LogDebug("+++++++++++++++++++++++++++++++")
    LogDebug("LinkedIn Client parsing access token result")
    t := new(linkedInAccessTokenResult)
    m, err := url.ParseQuery(value)
    if m != nil {
        t.token = m.Get("oauth_token")
        t.secret = m.Get("oauth_token_secret")
        strExpiresIn := m.Get("xoauth_authorization_expires_in")
        expiresIn, _ := strconv.Atoi64(strExpiresIn)
        if expiresIn > 0 {
            t.expiresAt = time.SecondsToUTC(time.Seconds() + expiresIn)
        }
        if err == nil && len(m.Get("oauth_problem")) > 0 {
            err = os.NewError(m.Get("oauth_problem"))
        }
    }
    LogDebug("+++++++++++++++++++++++++++++++")
    return t, err
}

func (p *linkedInClient) RetrieveUserInfo() (UserInfo, os.Error) {
    req, err := p.CreateAuthorizedRequest(_LINKEDIN_USERINFO_METHOD, nil, _LINKEDIN_USERINFO_URL, nil, nil)
    if err != nil {
        return nil, err
    }
    result := new(linkedInUserInfoResult)
    resp, _, err := MakeRequest(p.client, req)
    if resp != nil && resp.Body != nil {
        props := jsonhelper.NewJSONObject()
        if err2 := json.NewDecoder(resp.Body).Decode(&props); err == nil {
            err = err2
        }
        result.FromJSON(props)
    }
    return result, err
}
