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

type SmugMugUserInfoResult interface {
    Id()            string
    Name()          string
    Nickname()      string
    Url()           string
    AccountStatus() string
    AccountType()   string
    FileSizeLimit() float64
    SmugVault()     bool
}

type smugMugUserInfoResult struct {
    id              int64   `json:"id"`
    name            string  `json:"Name"`
    nickname        string  `json:"NickName"`
    url             string  `json:"URL"`
    accountStatus   string  `json:"AccountStatus"`
    accountType     string  `json:"AccountType"`
    fileSizeLimit   int64   `json:"FileSizeLimit"`
    smugVault       bool    `json:"SmugVault"`
}

func (p *smugMugUserInfoResult) Guid() string { return strconv.Itoa64(p.id) }
func (p *smugMugUserInfoResult) Username() string { return p.nickname }
func (p *smugMugUserInfoResult) GivenName() string {
    parts := strings.SplitN(p.name, " ", 2)
    return parts[0]
}
func (p *smugMugUserInfoResult) FamilyName() string {
    parts := strings.Split(p.name, " ")
    return parts[len(parts)-1]
}
func (p *smugMugUserInfoResult) DisplayName() string { return p.name }
func (p *smugMugUserInfoResult) Id() int64 { return p.id }
func (p *smugMugUserInfoResult) Name() string { return p.name }
func (p *smugMugUserInfoResult) Nickname() string { return p.nickname }
func (p *smugMugUserInfoResult) Url() string { return p.url }
func (p *smugMugUserInfoResult) AccountStatus() string { return p.accountStatus }
func (p *smugMugUserInfoResult) AccountType() string { return p.accountType }
func (p *smugMugUserInfoResult) FileSizeLimit() int64 { return p.fileSizeLimit }
func (p *smugMugUserInfoResult) SmugVault() bool { return p.smugVault }
func (p *smugMugUserInfoResult) FromJSON(props jsonhelper.JSONObject) {
    LogDebug("user info result from json: ", props)
    p.id = props.GetAsInt64("id")
    p.accountStatus = props.GetAsString("AccountStatus")
    p.accountType = props.GetAsString("AccountType")
    p.fileSizeLimit = props.GetAsInt64("FileSizeLimit")
    p.name = props.GetAsString("Name")
    p.nickname = props.GetAsString("NickName")
    p.smugVault = props.GetAsBool("SmugVault")
    p.url = props.GetAsString("URL")
}

type smugMugClient struct {
    stdOAuth1Client
    appName         string "app_name"
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

func (p *smugMugClient) RequestUrl() string { return _SMUGMUG_REQUEST_TOKEN_URL }
func (p *smugMugClient) RequestUrlMethod() string { return _SMUGMUG_REQUEST_TOKEN_METHOD }
func (p *smugMugClient) RequestUrlProtected() bool { return _SMUGMUG_REQUEST_TOKEN_PROTECTED }
func (p *smugMugClient) AccessUrl() string { return _SMUGMUG_ACCESS_TOKEN_URL }
func (p *smugMugClient) AccessUrlMethod() string  { return _SMUGMUG_ACCESS_TOKEN_METHOD }
func (p *smugMugClient) AccessUrlProtected() bool { return _SMUGMUG_ACCESS_TOKEN_PROTECTED }
func (p *smugMugClient) AuthorizationUrl() string { return _SMUGMUG_AUTHORIZATION_PATH_URL }
func (p *smugMugClient) AuthorizedResourceProtected() bool { return _SMUGMUG_AUTHORIZED_RESOURCE_PROTECTED }
func (p *smugMugClient) ServiceId() string { return "smugmug.com" }
func (p *smugMugClient) Initialize(properties jsonhelper.JSONObject) {
    if p.currentCredentials == nil {
        p.currentCredentials = NewStandardAuthToken()
    }
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
    if v := properties.GetAsString("smugmug.oauth1.scope"); len(v) > 0 {
        //p.Scope = v
    }
    if v := properties.GetAsString("smugmug.client.token"); len(v) > 0 {
        p.currentCredentials.SetToken(v)
    }
    if v := properties.GetAsString("smugmug.client.secret"); len(v) > 0 {
        p.currentCredentials.SetSecret(v)
    }
}

func (p *smugMugClient) GenerateRequestTokenUrl(properties jsonhelper.JSONObject) string {
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
    LogDebug("+++++++++++++++++++++++++++++++")
    LogDebug("SmugMug! Client parsing request token result")
    t, err := defaultOAuth1ParseAuthToken(value)
    LogDebug("+++++++++++++++++++++++++++++++")
    return t, err
}


func (p *smugMugClient) ParseAccessTokenResult(value string) (AuthToken, os.Error) {
    LogDebug("+++++++++++++++++++++++++++++++")
    LogDebug("SmugMug! Client parsing access token result")
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
    LogDebug("+++++++++++++++++++++++++++++++")
    return t, err
}

func (p *smugMugClient) RetrieveUserInfo() (UserInfo, os.Error) {
    req, err := p.CreateAuthorizedRequest(_SMUGMUG_USERINFO_METHOD, nil, _SMUGMUG_USERINFO_URL, nil, nil)
    if err != nil {
        return nil, err
    }
    result := new(smugMugUserInfoResult)
    resp, _, err := MakeRequest(p.client, req)
    if resp != nil && resp.Body != nil {
        props := jsonhelper.NewJSONObject()
        if err2 := json.NewDecoder(resp.Body).Decode(&props); err == nil {
            err = err2
        }
        result.FromJSON(props.GetAsObject("Auth").GetAsObject("User"))
    }
    return result, err
}



