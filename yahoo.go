package oauth2_client

import (
    "github.com/pomack/jsonhelper"
    "http"
    "io"
    "json"
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

type YahooUserInfoIm interface {
    Handle()            string
    Id()                int
    Type()              string
}

type YahooUserInfoEmail interface {
    YahooUserInfoIm
    IsPrimary()         bool
}

type YahooUserInfoResult interface {
    UserInfo
    Uri()               string
    BirthYear()         int
    Birthdate()         string
    Created()           *time.Time
    DisplayAge()        int
    Gender()            string
    Lang()              string
    Location()          string
    MemberSince()       *time.Time
    Nickname()          string
    ProfileUrl()        string
    Searchable()        bool
    TimeZone()          string
    Updated()           *time.Time
    IsConnected()       bool
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

type yahooUserInfoIm struct {
    handle          string  `json:"handle"`
    id              int     `json:"id"`
    theType         string  `json:"type"`
}

func (p *yahooUserInfoIm) Handle() string { return p.handle }
func (p *yahooUserInfoIm) Id() int { return p.id }
func (p *yahooUserInfoIm) Type() string { return p.theType }
func (p *yahooUserInfoIm) FromJSON(props jsonhelper.JSONObject) {
    p.handle = props.GetAsString("handle")
    p.id = props.GetAsInt("id")
    p.theType = props.GetAsString("type")
}

type yahooUserInfoEmail struct {
    yahooUserInfoIm
    isPrimary           bool    `json:"primary"`
}

func (p *yahooUserInfoEmail) IsPrimary() bool { return p.isPrimary }
func (p *yahooUserInfoEmail) FromJSON(props jsonhelper.JSONObject) {
    p.yahooUserInfoIm.FromJSON(props)
    p.isPrimary = props.GetAsBool("primary")
}

type yahooUserInfoResult struct {
    guid                string
    uri                 string
    birthYear           int
    birthdate           string
    created             *time.Time
    displayAge          int
    emails              []YahooUserInfoEmail
    familyName          string
    givenName           string
    gender              string
    ims                 []YahooUserInfoIm
    lang                string
    location            string
    memberSince         *time.Time
    nickname            string
    profileUrl          string
    searchable          bool
    timeZone            string
    updated             *time.Time
    isConnected         bool
}

func (p *yahooUserInfoResult) Guid()              string        { return p.guid }
func (p *yahooUserInfoResult) Username()          string        { return p.nickname }
func (p *yahooUserInfoResult) Url()               string        { return p.uri }
func (p *yahooUserInfoResult) DisplayName()       string        {
    if len(p.givenName) > 0 && len(p.familyName) > 0 {
        return p.givenName + " " + p.familyName
    }
    return p.givenName + p.familyName
}
func (p *yahooUserInfoResult) Uri()               string        { return p.uri }
func (p *yahooUserInfoResult) BirthYear()         int           { return p.birthYear }
func (p *yahooUserInfoResult) Birthdate()         string        { return p.birthdate }
func (p *yahooUserInfoResult) Created()           *time.Time    { return p.created }
func (p *yahooUserInfoResult) DisplayAge()        int           { return p.displayAge }
func (p *yahooUserInfoResult) Emails()            []YahooUserInfoEmail { return p.emails }
func (p *yahooUserInfoResult) FamilyName()        string        { return p.familyName }
func (p *yahooUserInfoResult) GivenName()         string        { return p.givenName }
func (p *yahooUserInfoResult) Gender()            string        { return p.gender }
func (p *yahooUserInfoResult) Ims()               []YahooUserInfoIm { return p.ims }
func (p *yahooUserInfoResult) Lang()              string        { return p.lang }
func (p *yahooUserInfoResult) Location()          string        { return p.location }
func (p *yahooUserInfoResult) MemberSince()       *time.Time    { return p.memberSince }
func (p *yahooUserInfoResult) Nickname()          string        { return p.nickname }
func (p *yahooUserInfoResult) ProfileUrl()        string        { return p.profileUrl }
func (p *yahooUserInfoResult) Searchable()        bool          { return p.searchable }
func (p *yahooUserInfoResult) TimeZone()          string        { return p.timeZone }
func (p *yahooUserInfoResult) Updated()           *time.Time    { return p.updated }
func (p *yahooUserInfoResult) IsConnected()       bool          { return p.isConnected }
func (p *yahooUserInfoResult) FromJSON(props jsonhelper.JSONObject) {
    p.guid = props.GetAsString("guid")
    p.uri = props.GetAsString("uri")
    p.birthYear = props.GetAsInt("birthYear")
    p.birthdate = props.GetAsString("birthdate")
    p.created = props.GetAsTime("created", YAHOO_DATETIME_FORMAT)
    p.displayAge = props.GetAsInt("displayAge")
    emails := props.GetAsArray("emails")
    p.emails = make([]YahooUserInfoEmail, len(emails))
    for i, email := range emails {
        v := new(yahooUserInfoEmail)
        v.FromJSON(jsonhelper.JSONValueToObject(email))
        p.emails[i] = v
    }
    p.familyName = props.GetAsString("familyName")
    p.givenName = props.GetAsString("givenName")
    p.gender = props.GetAsString("gender")
    ims := props.GetAsArray("ims")
    p.ims = make([]YahooUserInfoIm, len(ims))
    for i, im := range ims {
        v := new(yahooUserInfoIm)
        v.FromJSON(jsonhelper.JSONValueToObject(im))
        p.ims[i] = v
    }
    p.lang = props.GetAsString("lang")
    p.location = props.GetAsString("location")
    p.memberSince = props.GetAsTime("memberSince", YAHOO_DATETIME_FORMAT)
    p.nickname = props.GetAsString("nickname")
    p.profileUrl = props.GetAsString("profileUrl")
    p.searchable = props.GetAsBool("searchable")
    p.timeZone = props.GetAsString("timeZone")
    p.updated = props.GetAsTime("updated", YAHOO_DATETIME_FORMAT)
    p.isConnected = props.GetAsBool("isConnected")
}

func NewYahooClient() OAuth2Client {
    return &yahooClient{}
}

func (p *yahooClient) RequestUrl() string { return _YAHOO_REQUEST_TOKEN_URL }
func (p *yahooClient) RequestUrlMethod() string { return _YAHOO_REQUEST_TOKEN_METHOD }
func (p *yahooClient) RequestUrlProtected() bool { return _YAHOO_REQUEST_TOKEN_PROTECTED }
func (p *yahooClient) AccessUrl() string { return _YAHOO_ACCESS_TOKEN_URL }
func (p *yahooClient) AccessUrlMethod() string  { return _YAHOO_ACCESS_TOKEN_METHOD }
func (p *yahooClient) AccessUrlProtected() bool { return _YAHOO_ACCESS_TOKEN_PROTECTED }
func (p *yahooClient) AuthorizationUrl() string { return _YAHOO_AUTHORIZATION_PATH_URL }
func (p *yahooClient) AuthorizedResourceProtected() bool { return _YAHOO_AUTHORIZED_RESOURCE_PROTECTED }
func (p *yahooClient) ServiceId() string { return "yahoo.com" }
func (p *yahooClient) Initialize(properties jsonhelper.JSONObject) {
    if p.currentCredentials == nil {
        p.currentCredentials = NewStandardAuthToken()
    }
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
    if v := properties.GetAsString("yahoo.oauth1.scope"); len(v) > 0 {
        //p.Scope = v
    }
    if v := properties.GetAsString("yahoo.client.token"); len(v) > 0 {
        p.currentCredentials.SetToken(v)
    }
    if v := properties.GetAsString("yahoo.client.secret"); len(v) > 0 {
        p.currentCredentials.SetSecret(v)
    }
}

func (p *yahooClient) GenerateRequestTokenUrl(properties jsonhelper.JSONObject) string {
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
    LogDebug("+++++++++++++++++++++++++++++++")
    LogDebug("Yahoo! Client parsing request token result")
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
    LogDebug("+++++++++++++++++++++++++++++++")
    return t, err
}


func (p *yahooClient) ParseAccessTokenResult(value string) (AuthToken, os.Error) {
    LogDebug("+++++++++++++++++++++++++++++++")
    LogDebug("Yahoo! Client parsing access token result")
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
    LogDebug("+++++++++++++++++++++++++++++++")
    return t, err
}

func (p *yahooClient) RetrieveUserInfo() (UserInfo, os.Error) {
    req, err := p.CreateAuthorizedRequest(_YAHOO_USERINFO_METHOD, nil, _YAHOO_USERINFO_URL, nil, nil)
    if err != nil {
        return nil, err
    }
    result := new(yahooUserInfoResult)
    resp, _, err := MakeRequest(p.client, req)
    if resp != nil && resp.Body != nil {
        props := jsonhelper.NewJSONObject()
        if err2 := json.NewDecoder(resp.Body).Decode(&props); err == nil {
            err = err2
        }
        result.FromJSON(props.GetAsObject("profile"))
    }
    return result, err
}


