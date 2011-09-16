package oauth2_client

import (
    "http"
    "log"
    "io"
    "os"
    "strconv"
    "time"
    "url"
)

type LinkedInRequestTokenResult interface {
    AuthToken
    RequestAuthUrl()    string
    ExpiresAt()         *time.Time
    CallbackConfirmed() bool
}

type LinkedInAccessTokenResult interface {
    AuthToken
    ExpiresAt()     *time.Time
}

type linkedInRequestTokenResult struct {
    stdAuthToken
    requestAuthUrl      string
    expiresAt           *time.Time
    callbackConfirmed   bool
}

func (p *linkedInRequestTokenResult) RequestAuthUrl() string { return p.requestAuthUrl }
func (p *linkedInRequestTokenResult) ExpiresAt() *time.Time { return p.expiresAt }
func (p *linkedInRequestTokenResult) CallbackConfirmed() bool { return p.callbackConfirmed }

type linkedInAccessTokenResult struct {
    stdAuthToken
    expiresAt       *time.Time
}

func (p *linkedInAccessTokenResult) ExpiresAt() *time.Time { return p.expiresAt }


type linkedInClient struct {
    stdOAuth1Client
}

func NewLinkedInClient() OAuth2Client {
    return &linkedInClient{}
}

func (p *linkedInClient) Initialize(properties Properties) {
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
    if v := properties.GetAsString("linkedin.oauth1.request_token_path.url"); len(v) > 0 {
        p.requestUrl = v
        //p.TemporaryCredentialRequestURI = v
    }
    if v := properties.GetAsString("linkedin.oauth1.request_token_path.method"); len(v) > 0 {
        p.requestUrlMethod = v
    }
    if v := properties.GetAsBool("linkedin.oauth1.request_token_path.protected"); true {
        p.requestUrlProtected = v
    }
    if v := properties.GetAsString("linkedin.oauth1.authorization_path.url"); len(v) > 0 {
        p.authorizationUrl = v
        //p.ResourceOwnerAuthorizationURI = v
    }
    if v := properties.GetAsString("linkedin.oauth1.access_token_path.url"); len(v) > 0 {
        p.accessUrl = v
        //p.TokenRequestURI = v
    }
    if v := properties.GetAsString("linkedin.oauth1.access_token_path.method"); len(v) > 0 {
        p.accessUrlMethod = v
    }
    if v := properties.GetAsBool("linkedin.oauth1.access_token_path.protected"); true {
        p.accessUrlProtected = v
    }
    if v := properties.GetAsBool("linkedin.oauth1.authorized_resource.protected"); true {
        p.authorizedResourceProtected = v
    }
    if v := properties.GetAsString("linkedin.oauth1.scope"); len(v) > 0 {
        //p.Scope = v
    }
}

func (p *linkedInClient) GenerateRequestTokenUrl(properties Properties) string {
    return oauth1GenerateRequestTokenUrl(p, properties)
}

func (p *linkedInClient) RequestTokenGranted(req *http.Request) bool {
    return oauth1RequestTokenGranted(p, req)
}

func (p *linkedInClient) ExchangeRequestTokenForAccess(req *http.Request) os.Error {
    return oauth1ExchangeRequestTokenForAccess(p, req)
}

func (p *linkedInClient) CreateAuthorizedRequest(method string, headers http.Header, uri string, query url.Values, r io.Reader) (*http.Request, os.Error) {
    return oauth1CreateAuthorizedRequest(p, method, headers, uri, query, r)
}




func (p *linkedInClient) ParseRequestTokenResult(value string) (AuthToken, os.Error) {
    log.Print("+++++++++++++++++++++++++++++++")
    log.Print("LinkedIn Client parsing request token result")
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
    log.Print("+++++++++++++++++++++++++++++++")
    return t, err
}


func (p *linkedInClient) ParseAccessTokenResult(value string) (AuthToken, os.Error) {
    log.Print("+++++++++++++++++++++++++++++++")
    log.Print("LinkedIn Client parsing access token result")
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
    log.Print("+++++++++++++++++++++++++++++++")
    return t, err
}




