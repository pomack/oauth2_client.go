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

type smugMugClient struct {
    stdOAuth1Client
    appName     string "app_name"
}

type SmugMugAccessTokenResult interface {
    AuthToken
    Guid()          string
    SessionHandle() string
    ExpiresAt()     *time.Time
}

type smugMugAccessTokenResult struct {
    stdAuthToken
    guid            string
    sessionHandle   string
    expiresAt       *time.Time
}

func (p *smugMugAccessTokenResult) Guid() string { return p.guid }
func (p *smugMugAccessTokenResult) SessionHandle() string { return p.sessionHandle }
func (p *smugMugAccessTokenResult) ExpiresAt() *time.Time { return p.expiresAt }

func NewSmugMugClient() OAuth2Client {
    return &smugMugClient{}
}

func (p *smugMugClient) Initialize(properties Properties) {
    if properties == nil {
        return
    }
    if v := properties.GetAsString("smugmug.realm"); len(v) > 0 {
        p.realm = v
    }
    if v := properties.GetAsString("smugmug.app.name"); len(v) > 0 {
        p.appName = v
    }
    if v := properties.GetAsString("smugmug.consumer.key"); len(v) > 0 {
        p.consumerKey = v
        //p.Credentials.Token = v
    }
    if v := properties.GetAsString("smugmug.consumer.secret"); len(v) > 0 {
        p.consumerSecret = v
        //p.Credentials.Secret = v
    }
    if v := properties.GetAsString("smugmug.client.redirect_uri"); len(v) > 0 {
        p.callbackUrl = v
    }
    if v := properties.GetAsString("smugmug.oauth1.request_token_path.url"); len(v) > 0 {
        p.requestUrl = v
        //p.TemporaryCredentialRequestURI = v
    }
    if v := properties.GetAsString("smugmug.oauth1.request_token_path.method"); len(v) > 0 {
        p.requestUrlMethod = v
    }
    if v := properties.GetAsBool("smugmug.oauth1.request_token_path.protected"); true {
        p.requestUrlProtected = v
    }
    if v := properties.GetAsString("smugmug.oauth1.authorization_path.url"); len(v) > 0 {
        p.authorizationUrl = v
        //p.ResourceOwnerAuthorizationURI = v
    }
    if v := properties.GetAsString("smugmug.oauth1.access_token_path.url"); len(v) > 0 {
        p.accessUrl = v
        //p.TokenRequestURI = v
    }
    if v := properties.GetAsString("smugmug.oauth1.access_token_path.method"); len(v) > 0 {
        p.accessUrlMethod = v
    }
    if v := properties.GetAsBool("smugmug.oauth1.access_token_path.protected"); true {
        p.accessUrlProtected = v
    }
    if v := properties.GetAsBool("smugmug.oauth1.authorized_resource.protected"); true {
        p.authorizedResourceProtected = v
    }
    if v := properties.GetAsString("smugmug.oauth1.scope"); len(v) > 0 {
        //p.Scope = v
    }
}

func (p *smugMugClient) GenerateRequestTokenUrl(properties Properties) string {
    return oauth1GenerateRequestTokenUrl(p, properties)
}

func (p *smugMugClient) RequestTokenGranted(req *http.Request) bool {
    return oauth1RequestTokenGranted(p, req)
}

func (p *smugMugClient) ExchangeRequestTokenForAccess(req *http.Request) os.Error {
    return oauth1ExchangeRequestTokenForAccess(p, req)
}

func (p *smugMugClient) CreateAuthorizedRequest(method string, headers http.Header, uri string, query url.Values, r io.Reader) (*http.Request, os.Error) {
    return oauth1CreateAuthorizedRequest(p, method, headers, uri, query, r)
}


func (p *smugMugClient) ParseRequestTokenResult(value string) (AuthToken, os.Error) {
    log.Print("+++++++++++++++++++++++++++++++")
    log.Print("SmugMug! Client parsing request token result")
    t, err := defaultOAuth1ParseAuthToken(value)
    log.Print("+++++++++++++++++++++++++++++++")
    return t, err
}


func (p *smugMugClient) ParseAccessTokenResult(value string) (AuthToken, os.Error) {
    log.Print("+++++++++++++++++++++++++++++++")
    log.Print("SmugMug! Client parsing access token result")
    t := new(smugMugAccessTokenResult)
    m, err := url.ParseQuery(value)
    if m != nil {
        t.token = m.Get("oauth_token")
        t.secret = m.Get("oauth_token_secret")
        t.guid = m.Get("xoauth_smugMug_guid")
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


