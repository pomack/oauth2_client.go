package oauth2_client

import (
    "http"
    "log"
    "os"
    "url"
    "io"
)

type TwitterRequestTokenResult interface {
    AuthToken
    CallbackConfirmed() bool
}

type TwitterAccessTokenResult interface {
    AuthToken
    UserId()        string
    ScreenName()    string
}

type twitterRequestTokenResult struct {
    stdAuthToken
    callbackConfirmed   bool
}

func (p *twitterRequestTokenResult) CallbackConfirmed() bool { return p.callbackConfirmed }

type twitterAccessTokenResult struct {
    stdAuthToken
    userId          string
    screenName      string
}

func (p *twitterAccessTokenResult) UserId() string { return p.userId }
func (p *twitterAccessTokenResult) ScreenName() string { return p.screenName }


type twitterClient struct {
    stdOAuth1Client
}

func NewTwitterClient() OAuth2Client {
    return &twitterClient{}
}

func (p *twitterClient) Initialize(properties Properties) {
    if properties == nil {
        return
    }
    if v := properties.GetAsString("twitter.consumer.key"); len(v) > 0 {
        p.consumerKey = v
        //p.Credentials.Token = v
    }
    if v := properties.GetAsString("twitter.consumer.secret"); len(v) > 0 {
        p.consumerSecret = v
        //p.Credentials.Secret = v
    }
    if v := properties.GetAsString("twitter.callback_url"); len(v) > 0 {
        p.callbackUrl = v
    }
    if v := properties.GetAsString("twitter.oauth1.request_token_path.url"); len(v) > 0 {
        p.requestUrl = v
        //p.TemporaryCredentialRequestURI = v
    }
    if v := properties.GetAsString("twitter.oauth1.request_token_path.method"); len(v) > 0 {
        p.requestUrlMethod = v
    }
    if v := properties.GetAsBool("twitter.oauth1.request_token_path.protected"); true {
        p.requestUrlProtected = v
    }
    if v := properties.GetAsString("twitter.oauth1.authorization_path.url"); len(v) > 0 {
        p.authorizationUrl = v
        //p.ResourceOwnerAuthorizationURI = v
    }
    if v := properties.GetAsString("twitter.oauth1.access_token_path.url"); len(v) > 0 {
        p.accessUrl = v
        //p.TokenRequestURI = v
    }
    if v := properties.GetAsString("twitter.oauth1.access_token_path.method"); len(v) > 0 {
        p.accessUrlMethod = v
    }
    if v := properties.GetAsBool("twitter.oauth1.access_token_path.protected"); true {
        p.accessUrlProtected = v
    }
    if v := properties.GetAsBool("twitter.oauth1.authorized_resource.protected"); true {
        p.authorizedResourceProtected = v
    }
    if v := properties.GetAsString("twitter.oauth1.scope"); len(v) > 0 {
        //p.Scope = v
    }
}

func (p *twitterClient) GenerateRequestTokenUrl(properties Properties) string {
    return oauth1GenerateRequestTokenUrl(p, properties)
}

func (p *twitterClient) RequestTokenGranted(req *http.Request) bool {
    return oauth1RequestTokenGranted(p, req)
}

func (p *twitterClient) ExchangeRequestTokenForAccess(req *http.Request) os.Error {
    return oauth1ExchangeRequestTokenForAccess(p, req)
}

func (p *twitterClient) CreateAuthorizedRequest(method string, headers http.Header, uri string, query url.Values, r io.Reader) (*http.Request, os.Error) {
    return oauth1CreateAuthorizedRequest(p, method, headers, uri, query, r)
}



func (p *twitterClient) ParseRequestTokenResult(value string) (AuthToken, os.Error) {
    log.Print("+++++++++++++++++++++++++++++++")
    log.Print("Twitter Client parsing request token result")
    t := new(twitterRequestTokenResult)
    m, err := url.ParseQuery(value)
    if m != nil {
        t.token = m.Get("oauth_token")
        t.secret = m.Get("oauth_token_secret")
        t.callbackConfirmed = m.Get("oauth_callback_confirmed") == "true"
        if err == nil && len(m.Get("oauth_problem")) > 0 {
            err = os.NewError(m.Get("oauth_problem"))
        }
    }
    log.Print("+++++++++++++++++++++++++++++++")
    return t, err
}


func (p *twitterClient) ParseAccessTokenResult(value string) (AuthToken, os.Error) {
    log.Print("+++++++++++++++++++++++++++++++")
    log.Print("Twitter Client parsing access token result")
    t := new(twitterAccessTokenResult)
    m, err := url.ParseQuery(value)
    if m != nil {
        t.token = m.Get("oauth_token")
        t.secret = m.Get("oauth_token_secret")
        t.userId = m.Get("user_id")
        t.screenName = m.Get("screen_name")
        if err == nil && len(m.Get("oauth_problem")) > 0 {
            err = os.NewError(m.Get("oauth_problem"))
        }
    }
    log.Print("+++++++++++++++++++++++++++++++")
    return t, err
}





