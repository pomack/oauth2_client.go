package oauth2_client

import (
    "http"
    "io"
    "log"
    "os"
    "strconv"
    "time"
    "url"
)

type yahooClient struct {
    stdOAuth1Client
}

type YahooRequestTokenResult interface {
    AuthToken
    RequestAuthUrl()    string
    ExpiresAt()         *time.Time
    CallbackConfirmed() bool
}

type YahooAccessTokenResult interface {
    AuthToken
    Guid()          string
    SessionHandle() string
    ExpiresAt()     *time.Time
}

type yahooRequestTokenResult struct {
    stdAuthToken
    requestAuthUrl      string
    expiresAt           *time.Time
    callbackConfirmed   bool
}

func (p *yahooRequestTokenResult) RequestAuthUrl() string { return p.requestAuthUrl }
func (p *yahooRequestTokenResult) ExpiresAt() *time.Time { return p.expiresAt }
func (p *yahooRequestTokenResult) CallbackConfirmed() bool { return p.callbackConfirmed }

type yahooAccessTokenResult struct {
    stdAuthToken
    guid            string
    sessionHandle   string
    expiresAt       *time.Time
}

func (p *yahooAccessTokenResult) Guid() string { return p.guid }
func (p *yahooAccessTokenResult) SessionHandle() string { return p.sessionHandle }
func (p *yahooAccessTokenResult) ExpiresAt() *time.Time { return p.expiresAt }

func NewYahooClient() OAuth2Client {
    return &yahooClient{}
}

func (p *yahooClient) Initialize(properties Properties) {
    if properties == nil {
        return
    }
    if v := properties.GetAsString("yahoo.realm"); len(v) > 0 {
        p.realm = v
    }
    if v := properties.GetAsString("yahoo.consumer.key"); len(v) > 0 {
        p.consumerKey = v
        //p.Credentials.Token = v
    }
    if v := properties.GetAsString("yahoo.consumer.secret"); len(v) > 0 {
        p.consumerSecret = v
        //p.Credentials.Secret = v
    }
    if v := properties.GetAsString("yahoo.client.redirect_uri"); len(v) > 0 {
        p.callbackUrl = v
    }
    if v := properties.GetAsString("yahoo.oauth1.request_token_path.url"); len(v) > 0 {
        p.requestUrl = v
        //p.TemporaryCredentialRequestURI = v
    }
    if v := properties.GetAsString("yahoo.oauth1.request_token_path.method"); len(v) > 0 {
        p.requestUrlMethod = v
    }
    if v := properties.GetAsBool("yahoo.oauth1.request_token_path.protected"); true {
        p.requestUrlProtected = v
    }
    if v := properties.GetAsString("yahoo.oauth1.authorization_path.url"); len(v) > 0 {
        p.authorizationUrl = v
        //p.ResourceOwnerAuthorizationURI = v
    }
    if v := properties.GetAsString("yahoo.oauth1.access_token_path.url"); len(v) > 0 {
        p.accessUrl = v
        //p.TokenRequestURI = v
    }
    if v := properties.GetAsString("yahoo.oauth1.access_token_path.method"); len(v) > 0 {
        p.accessUrlMethod = v
    }
    if v := properties.GetAsBool("yahoo.oauth1.access_token_path.protected"); true {
        p.accessUrlProtected = v
    }
    if v := properties.GetAsBool("yahoo.oauth1.authorized_resource.protected"); true {
        p.authorizedResourceProtected = v
    }
    if v := properties.GetAsString("yahoo.oauth1.scope"); len(v) > 0 {
        //p.Scope = v
    }
}

func (p *yahooClient) GenerateRequestTokenUrl(properties Properties) string {
    return oauth1GenerateRequestTokenUrl(p, properties)
}

func (p *yahooClient) RequestTokenGranted(req *http.Request) bool {
    return oauth1RequestTokenGranted(p, req)
}

func (p *yahooClient) ExchangeRequestTokenForAccess(req *http.Request) os.Error {
    return oauth1ExchangeRequestTokenForAccess(p, req)
}

func (p *yahooClient) CreateAuthorizedRequest(method string, headers http.Header, uri string, query url.Values, r io.Reader) (*http.Request, os.Error) {
    return oauth1CreateAuthorizedRequest(p, method, headers, uri, query, r)
}


func (p *yahooClient) ParseRequestTokenResult(value string) (AuthToken, os.Error) {
    log.Print("+++++++++++++++++++++++++++++++")
    log.Print("Yahoo! Client parsing request token result")
    t := new(yahooRequestTokenResult)
    m, err := url.ParseQuery(value)
    if m != nil {
        t.token = m.Get("oauth_token")
        t.secret = m.Get("oauth_token_secret")
        t.requestAuthUrl = m.Get("xoauth_request_auth_url")
        t.callbackConfirmed = m.Get("oauth_callback_confirmed") == "true"
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


func (p *yahooClient) ParseAccessTokenResult(value string) (AuthToken, os.Error) {
    log.Print("+++++++++++++++++++++++++++++++")
    log.Print("Yahoo! Client parsing access token result")
    t := new(yahooAccessTokenResult)
    m, err := url.ParseQuery(value)
    if m != nil {
        t.token = m.Get("oauth_token")
        t.secret = m.Get("oauth_token_secret")
        t.guid = m.Get("xoauth_yahoo_guid")
        t.sessionHandle = m.Get("oauth_session_handle")
        strExpiresIn := m.Get("oauth_authorization_expires_in")
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


