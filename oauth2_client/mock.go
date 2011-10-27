package oauth2_client

import (
    "github.com/pomack/jsonhelper.go/jsonhelper"
    "container/vector"
    "http"
    "io"
    "os"
    "reflect"
    "strings"
    "time"
    "url"
)

type MockRequestHandler func(req *http.Request) (resp *http.Response, err os.Error)

// Credentials represents client, temporary and token credentials.
type MockAuthToken interface {
    // Also known as consumer key or access token.
    Token() string
    // Also known as consumer secret or access token secret.
    Secret() string
    SetToken(value string)
    SetSecret(value string)
    Guid() string
    SetGuid(guid string)
    SessionHandle() string
    SetSessionHandle(handle string)
    ExpiresAt() *time.Time
    SetExpiresAt(expiresAt *time.Time)
    UserId() string
    SetUserId(userId string)
    ScreenName() string
    SetScreenName(screenName string)
}

type mockAuthToken struct {
    token  string
    secret string
    guid string
    sessionHandle string
    expiresAt *time.Time
    userId string
    screenName string
}

func NewMockAuthToken() MockAuthToken {
    return &mockAuthToken{}
}

type MockClient interface {
    OAuth2Client
    SetServiceId(serviceId string)
    SetClient(client *http.Client)
    SetGenerateRequestTokenUrl(value string)
    SetRequestTokenGranted(req *http.Request, value bool)
    SetExchangeRequestTokenForAccess(req *http.Request, error os.Error)
    SetRetrieveUserInfo(userInfo UserInfo, error os.Error)
    CurrentCredentials() AuthToken
    SetCurrentCredentials(value AuthToken)
    Realm() string
    SetRealm(realm string)
    ConsumerKey() string
    SetConsumerKey(consumerKey string)
    ConsumerSecret() string
    SetConsumerSecret(consumerSecret string)
    RequestUrl() string
    SetRequestUrl(requestUrl string)
    RequestUrlMethod() string
    SetRequestUrlMethod(method string)
    RequestUrlProtected() bool
    SetRequestUrlProtected(protected bool)
    AccessUrl() string
    SetAccessUrl(accessUrl string)
    AccessUrlMethod() string
    SetAccessUrlMethod(method string)
    AccessUrlProtected() bool
    SetAccessUrlProtected(protected bool)
    AuthorizationUrl() string
    SetAuthorizationUrl(authorizationUrl string)
    AuthorizedResourceProtected() bool
    SetAuthorizedResourceProtected(protected bool)
    CallbackUrl() string
    SetCallbackUrl(callbackUrl string)
    ParseRequestTokenResult(value string) (AuthToken, os.Error)
    SetParseRequestTokenResult(value string, respToken MockAuthToken, respError os.Error)
    ParseAccessTokenResult(value string) (AuthToken, os.Error)
    SetParseAccessTokenResult(value string, respToken MockAuthToken, respError os.Error)
    SetRequestHandler(handler MockRequestHandler)
    HandleRequest(req *http.Request) (resp *http.Response, err os.Error)
}

type mockParseTokenResult struct {
  Token MockAuthToken
  Error os.Error
}

type mockOAuthClient struct {
    client              *http.Client
    currentCredentials  MockAuthToken
    serviceName         string
    realm               string
    consumerKey         string
    consumerSecret      string
    requestUrl          string
    requestUrlMethod    string
    requestUrlProtected bool
    accessUrl           string
    accessUrlMethod     string
    accessUrlProtected  bool
    authorizationUrl    string
    authorizedResourceProtected bool
    callbackUrl         string
    requestTokenUrl     string
    requestTokenResults map[string]mockParseTokenResult
    accessTokenResults  map[string]mockParseTokenResult
    exchangeRequestTokenForAccess vector.Vector
    exchangeRequestTokenForAccessResponse vector.Vector
    requestTokenGranted vector.Vector
    requestTokenGrantedResponse vector.Vector
    createAuthorizedRequest vector.Vector
    createAuthorizedRequestResponse vector.Vector
    userinfo            UserInfo
    userinfoError       os.Error
    requestHandler      MockRequestHandler
}

type mockSecretInfo struct {
    service string
    token   string
    secret  string
}

func (p *mockAuthToken) Token() string                   { return p.token }
func (p *mockAuthToken) Secret() string                  { return p.secret }
func (p *mockAuthToken) SetToken(value string)           { p.token = value }
func (p *mockAuthToken) SetSecret(value string)          { p.secret = value }
func (p *mockAuthToken) Guid() string                    { return p.guid }
func (p *mockAuthToken) SetGuid(value string)            { p.guid = value }
func (p *mockAuthToken) SessionHandle() string           { return p.sessionHandle }
func (p *mockAuthToken) SetSessionHandle(value string)   { p.sessionHandle = value }
func (p *mockAuthToken) ExpiresAt() *time.Time           { return p.expiresAt }
func (p *mockAuthToken) SetExpiresAt(value *time.Time)   { p.expiresAt = value }
func (p *mockAuthToken) UserId() string                  { return p.userId }
func (p *mockAuthToken) SetUserId(value string)          { p.userId = value }
func (p *mockAuthToken) ScreenName() string              { return p.screenName }
func (p *mockAuthToken) SetScreenName(value string)      { p.screenName = value }

func NewMockOAuthClient() MockClient {
    return &mockOAuthClient{
        requestTokenResults:make(map[string]mockParseTokenResult),
        accessTokenResults:make(map[string]mockParseTokenResult),
    }
}

func (p *mockOAuthClient) Client() *http.Client {
    if p.client == nil {
        p.client = new(http.Client)
    }
    return p.client
}
func (p *mockOAuthClient) SetClient(value *http.Client)          { p.client = value }
func (p *mockOAuthClient) CurrentCredentials() AuthToken         { return p.currentCredentials }
func (p *mockOAuthClient) SetCurrentCredentials(value AuthToken) { p.currentCredentials = value.(MockAuthToken) }
func (p *mockOAuthClient) Realm() string                         { return p.realm }
func (p *mockOAuthClient) SetRealm(value string)                 { p.realm = value }
func (p *mockOAuthClient) ConsumerKey() string                   { return p.consumerKey }
func (p *mockOAuthClient) SetConsumerKey(value string)           { p.consumerKey = value }
func (p *mockOAuthClient) ConsumerSecret() string                { return p.consumerSecret }
func (p *mockOAuthClient) SetConsumerSecret(value string)        { p.consumerSecret = value }
func (p *mockOAuthClient) RequestUrl() string                    { return p.requestUrl }
func (p *mockOAuthClient) SetRequestUrl(value string)            { p.requestUrl = value }
func (p *mockOAuthClient) RequestUrlMethod() string              { return p.requestUrlMethod }
func (p *mockOAuthClient) SetRequestUrlMethod(value string)      { p.requestUrlMethod = value }
func (p *mockOAuthClient) RequestUrlProtected() bool             { return p.requestUrlProtected }
func (p *mockOAuthClient) SetRequestUrlProtected(value bool)     { p.requestUrlProtected = value }
func (p *mockOAuthClient) AccessUrl() string                     { return p.requestUrl }
func (p *mockOAuthClient) SetAccessUrl(value string)             { p.accessUrl = value }
func (p *mockOAuthClient) AccessUrlMethod() string               { return p.accessUrlMethod }
func (p *mockOAuthClient) SetAccessUrlMethod(value string)       { p.accessUrlMethod = value }
func (p *mockOAuthClient) AccessUrlProtected() bool              { return p.accessUrlProtected }
func (p *mockOAuthClient) SetAccessUrlProtected(value bool)      { p.accessUrlProtected = value }
func (p *mockOAuthClient) AuthorizationUrl() string              { return p.authorizationUrl }
func (p *mockOAuthClient) SetAuthorizationUrl(value string)      { p.authorizationUrl = value }
func (p *mockOAuthClient) AuthorizedResourceProtected() bool     { return p.authorizedResourceProtected }
func (p *mockOAuthClient) SetAuthorizedResourceProtected(value bool) { p.authorizedResourceProtected = value }
func (p *mockOAuthClient) CallbackUrl() string                   { return p.callbackUrl }
func (p *mockOAuthClient) SetCallbackUrl(value string)           { p.callbackUrl = value }
func (p *mockOAuthClient) SetParseRequestTokenResult(value string, token MockAuthToken, error os.Error) {
    p.requestTokenResults[value] = mockParseTokenResult{
      Token:token,
      Error:error,
    }
}
func (p *mockOAuthClient) SetParseAccessTokenResult(value string, token MockAuthToken, error os.Error) {
    p.accessTokenResults[value] = mockParseTokenResult{
      Token:token,
      Error:error,
    }
}


func (p *mockOAuthClient) ParseRequestTokenResult(value string) (AuthToken, os.Error) {
    res, ok := p.requestTokenResults[value]
    if ok {
        return res.Token, res.Error
    }
    return nil, nil
}

func (p *mockOAuthClient) ParseAccessTokenResult(value string) (AuthToken, os.Error) {
    res, ok := p.accessTokenResults[value]
    if ok {
        return res.Token, res.Error
    }
    return nil, nil
}

func (p *mockOAuthClient) ServiceId() string                                                { return p.serviceName }
func (p *mockOAuthClient) SetServiceId(value string)                                        { p.serviceName = value }
func (p *mockOAuthClient) Initialize(properties jsonhelper.JSONObject)                      {}
func (p *mockOAuthClient) GenerateRequestTokenUrl(properties jsonhelper.JSONObject) string  { return p.requestTokenUrl }
func (p *mockOAuthClient) SetGenerateRequestTokenUrl(value string)                          { p.requestTokenUrl = value }
func (p *mockOAuthClient) RequestTokenGranted(req *http.Request) bool                       {
    for i, v := range p.requestTokenGranted {
        if r, ok := v.(*http.Request); ok {
            if reflect.DeepEqual(r, req) {
                return p.requestTokenGrantedResponse[i].(bool)
            }
        }
    }
    return true
}
func (p *mockOAuthClient) SetRequestTokenGranted(req *http.Request, value bool)             {
    p.requestTokenGranted.Push(req)
    p.requestTokenGrantedResponse.Push(value)
}
func (p *mockOAuthClient) ExchangeRequestTokenForAccess(req *http.Request) os.Error {
    for i, v := range p.exchangeRequestTokenForAccess {
        if r, ok := v.(*http.Request); ok {
            if reflect.DeepEqual(r, req) {
                return p.exchangeRequestTokenForAccessResponse[i].(os.Error)
            }
        }
    }
    return nil
}
func (p *mockOAuthClient) SetExchangeRequestTokenForAccess(req *http.Request, error os.Error)             {
    p.exchangeRequestTokenForAccess.Push(req)
    p.exchangeRequestTokenForAccessResponse.Push(error)
}
func (p *mockOAuthClient) CreateAuthorizedRequest(method string, headers http.Header, uri string, query url.Values, r io.Reader) (req *http.Request, err os.Error) {
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
    if err != nil {
        return nil, err
    }
    fullUrl := MakeUrl(uri, query)
    req, err = http.NewRequest(method, fullUrl, r)
    if req != nil {
        req.Header = headers
    }
    return req, err
}
func (p *mockOAuthClient) RetrieveUserInfo() (UserInfo, os.Error) { return p.userinfo, p.userinfoError }
func (p *mockOAuthClient) SetRetrieveUserInfo(value UserInfo, error os.Error) { p.userinfo, p.userinfoError = value, error }

func (p *mockOAuthClient) SetRequestHandler(handler MockRequestHandler) {
    p.requestHandler = handler
}
func (p *mockOAuthClient) HandleRequest(req *http.Request) (*http.Response, os.Error) {
    if p.requestHandler == nil {
        return nil, nil
    }
    return p.requestHandler(req)
}
