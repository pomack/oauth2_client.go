package oauth2_client

import (
    "github.com/pomack/jsonhelper"
    "bytes"
    "http"
    "fmt"
    "io"
    "io/ioutil"
    "json"
    "os"
    "strconv"
    "strings"
    "time"
    "url"
)

type FacebookAccessTokenResult interface {
    AccessToken()   string
    ExpiresAt()     *time.Time
}

type facebookAccessTokenResult struct {
    accessToken     string
    expiresAt       *time.Time
}

func (p *facebookAccessTokenResult) AccessToken() string { return p.accessToken }
func (p *facebookAccessTokenResult) ExpiresAt() *time.Time { return p.expiresAt }

type FacebookLocation interface {
    Id()                string
    Name()              string
}

type facebookLocation struct {
    id                  string  `json:"id"`
    name                string  `json:"name"`
}

func (p *facebookLocation) Id() string { return p.id }
func (p *facebookLocation) Name() string { return p.name }
func (p *facebookLocation) UnmarshalJSON(data []byte) os.Error {
    props := jsonhelper.NewJSONObject()
    err := json.Unmarshal(data, &props)
    p.id = props.GetAsString("id")
    p.name = props.GetAsString("name")
    return err
}
func (p *facebookLocation) FromJSON(props jsonhelper.JSONObject) {
    p.id = props.GetAsString("id")
    p.name = props.GetAsString("name")
}

type FacebookUserInfoResult interface {
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

type facebookUserInfoResult struct {
    id                  string              `json:"id"`
    name                string              `json:"name"`
    firstName           string              `json:"first_name"`
    lastName            string              `json:"last_name"`
    link                string              `json:"link"`
    username            string              `json:"username"`
    hometown            facebookLocation    `json:"hometown"`
    location            facebookLocation    `json:"location"`
    gender              string              `json:"gender"`
    email               string              `json:"email"`
    timezone            float64             `json:"timezone"`
    locale              string              `json:"locale"`
    verified            bool                `json:"verified"`
    updatedTime         *time.Time          `json:"updated_time"`
}

func (p *facebookUserInfoResult) Guid() string { return p.id }
func (p *facebookUserInfoResult) Username() string { return p.username }
func (p *facebookUserInfoResult) GivenName() string { return p.firstName }
func (p *facebookUserInfoResult) FamilyName() string { return p.lastName }
func (p *facebookUserInfoResult) DisplayName() string { return p.name }
func (p *facebookUserInfoResult) Url() string { return p.link }
func (p *facebookUserInfoResult) Id() string { return p.id }
func (p *facebookUserInfoResult) Name() string { return p.name }
func (p *facebookUserInfoResult) FirstName() string { return p.firstName }
func (p *facebookUserInfoResult) LastName() string { return p.lastName }
func (p *facebookUserInfoResult) Link() string { return p.link }
func (p *facebookUserInfoResult) Hometown() FacebookLocation { return &p.hometown }
func (p *facebookUserInfoResult) Location() FacebookLocation { return &p.location }
func (p *facebookUserInfoResult) Gender() string { return p.gender }
func (p *facebookUserInfoResult) Email() string { return p.email }
func (p *facebookUserInfoResult) Timezone() float64 { return p.timezone }
func (p *facebookUserInfoResult) Locale() string { return p.locale }
func (p *facebookUserInfoResult) Verified() bool { return p.verified }
func (p *facebookUserInfoResult) UpdatedTime() *time.Time { return p.updatedTime }
func (p *facebookUserInfoResult) UnmarshalJSON(data []byte) os.Error {
    props := jsonhelper.NewJSONObject()
    err := json.Unmarshal(data, &props)
    p.id = props.GetAsString("id")
    p.name = props.GetAsString("name")
    p.firstName = props.GetAsString("first_name")
    p.lastName = props.GetAsString("last_name")
    p.link = props.GetAsString("link")
    p.username = props.GetAsString("username")
    p.hometown.FromJSON(props.GetAsObject("hometown"))
    p.location.FromJSON(props.GetAsObject("location"))
    p.gender = props.GetAsString("gender")
    p.email = props.GetAsString("email")
    p.timezone = props.GetAsFloat64("timezone")
    p.locale = props.GetAsString("locale")
    p.verified = props.GetAsBool("verified")
    p.updatedTime = props.GetAsTime("updated_time", FACEBOOK_DATETIME_FORMAT)
    return err
}

type facebookClient struct {
    client          *http.Client
    clientId        string "client_id"
    clientSecret    string "client_secret"
    redirectUri     string "redirect_uri"
    scope           string "scope"
    state           string "state"
    accessToken     string "access_token"
    expiresAt       *time.Time "expires_at"
    tokenType       string "token_type"
    refreshToken    string "refresh_token"
}

func NewFacebookClient() *facebookClient {
    return &facebookClient{client:new(http.Client)}
}
func (p *facebookClient) ClientId() string { return p.clientId }
func (p *facebookClient) ClientSecret() string { return p.clientSecret }
func (p *facebookClient) RedirectUri() string { return p.redirectUri }
func (p *facebookClient) AccessToken() string { return p.accessToken }
func (p *facebookClient) ExpiresAt() *time.Time { return p.expiresAt }
func (p *facebookClient) ExpiresAtString() string {
    if p.expiresAt == nil {
        return ""
    }
    return p.expiresAt.Format(FACEBOOK_DATETIME_FORMAT)
}
func (p *facebookClient) TokenType() string { return p.tokenType }
func (p *facebookClient) RefreshToken() string { return p.refreshToken }

func (p *facebookClient) ServiceId() string { return "facebook.com" }
func (p *facebookClient) Client() *http.Client {
    return p.client
}

func (p *facebookClient) Initialize(properties jsonhelper.JSONObject) {
    if properties == nil || len(properties) <= 0 {
        return
    }
    if v, ok := properties["facebook.client.id"]; ok {
        p.clientId = v.(string)
    }
    if v, ok := properties["facebook.client.secret"]; ok {
        p.clientSecret = v.(string)
    }
    if v, ok := properties["facebook.client.redirect_uri"]; ok {
        p.redirectUri = v.(string)
    }
    if v, ok := properties["facebook.client.scope"]; ok {
        p.scope = v.(string)
    }
    if v, ok := properties["facebook.client.state"]; ok {
        p.state = v.(string)
    }
    if v, ok := properties["facebook.client.access_token"]; ok {
        p.accessToken = v.(string)
    }
    if v, ok := properties["facebook.client.expires_at"]; ok {
        seconds, err := strconv.Atoi64(v.(string))
        if err == nil {
            p.expiresAt = time.SecondsToUTC(time.Seconds() + seconds)
        } else {
            if expiresAt, err := time.Parse(FACEBOOK_DATETIME_FORMAT, v.(string)); err == nil {
                p.expiresAt = expiresAt
            }
        }
    }
    if v, ok := properties["facebook.client.token_type"]; ok {
        p.tokenType = v.(string)
    }
    if v, ok := properties["facebook.client.refresh_token"]; ok {
        p.refreshToken = v.(string)
    }
}

func (p *facebookClient) Scope() string {
    return p.scope
}

func (p *facebookClient) SetScope(scope string) {
    p.scope = scope
}

func (p *facebookClient) State() string {
    return p.state
}

func (p *facebookClient) SetState(state string) {
    p.state = state
}

func (p *facebookClient) GenerateAuthorizationCodeUri(code string) (string, url.Values) {
    m := make(url.Values)
    //m.Add("grant_type", "authorization_code")
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
    return _FACEBOOK_AUTHORIZATION_CODE_URL, m
}

func (p *facebookClient) ReadAccessTokenFromResponse(r *http.Response, now *time.Time) os.Error {
    body_bytes, err := ioutil.ReadAll(r.Body)
    if err != nil {
        LogError("Unable to read the response from ", r.Body)
        return err
    }
    body := string(body_bytes)
    return p.ReadAccessToken(body, now)
}

func (p *facebookClient) ReadAccessToken(body string, now *time.Time) os.Error {
    params, err := url.ParseQuery(body)
    if err != nil {
        s := jsonhelper.NewJSONObject()
        if err2 := json.Unmarshal([]byte(body), &s); err2 != nil {
            LogError("Unable to read error response: ", body)
            return err2
        }
        return os.NewError(fmt.Sprintf("%v", s))
    }
    if params == nil {
        params = make(url.Values)
    }
    t := &facebookAccessTokenResult{accessToken:params.Get("access_token")}
    if len(params.Get("expires")) > 0 {
        expiresIn, _ := strconv.Atoi64(params.Get("expires"))
        if expiresIn >= 0 {
            t.expiresAt = time.SecondsToUTC(now.Seconds() + expiresIn)
        }
    }
    if len(t.accessToken) > 0 {
        p.expiresAt = t.expiresAt
        p.accessToken = t.accessToken
    }
    return nil
    
}

func (p *facebookClient) HandleClientAccept(code string) os.Error {
    now := time.UTC()
    uri, m := p.GenerateAuthorizationCodeUri(code)
    req, err := http.NewRequest(_FACEBOOK_AUTHORIZATION_CODE_METHOD, uri, bytes.NewBufferString(m.Encode()))
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
    return p.ReadAccessTokenFromResponse(r, now)
}

func (p *facebookClient) HandleClientAcceptRequest(req *http.Request) os.Error {
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

func (p *facebookClient) UpdateAccessToken() (string, os.Error) {
    now := time.UTC()
    if p.expiresAt == nil || p.expiresAt.Seconds() <= now.Seconds() {
        m := make(url.Values)
        m.Add("client_id", p.clientId)
        m.Add("client_secret", p.clientSecret)
        m.Add("refresh_token", p.refreshToken)
        m.Add("grant_type", "refresh_token")
        req, err := http.NewRequest(_FACEBOOK_REFRESH_TOKEN_METHOD, _FACEBOOK_REFRESH_TOKEN_URL, bytes.NewBufferString(m.Encode()))
        if err != nil {
            LogError("Unable to retrieve generate authorization code uri")
            return "", err
        }
        req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
        r, _, err := MakeRequest(p.client, req)
        //r, err := http.PostForm("https://accounts.google.com/o/oauth2/token", m)
        if err != nil {
            return "", err
        }
        err = p.ReadAccessTokenFromResponse(r, now)
        if err != nil {
            return "", err
        }
    }
    return p.accessToken, nil
}

func (p *facebookClient) GenerateRequestTokenUrl(properties jsonhelper.JSONObject) string {
    if properties == nil {
        properties = jsonhelper.NewJSONObject()
    }
    m := make(url.Values)
    //m.Add("response_type", "code")
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
    return MakeUrl(_FACEBOOK_ACCESS_TOKEN_URL, m)
}

func (p *facebookClient) RequestTokenGranted(req *http.Request) bool {
    if err := p.HandleClientAcceptRequest(req); err != nil {
        LogError("Error in client accept request: ", err.String())
        return false
    }
    return true
}

func (p *facebookClient) ExchangeRequestTokenForAccess(req *http.Request) os.Error {
    if len(p.refreshToken) <= 0 {
        if err := p.HandleClientAcceptRequest(req); err != nil {
            return err
        }
    }
    _, err := p.UpdateAccessToken()
    return err
}

func (p *facebookClient) CreateAuthorizedRequest(method string, headers http.Header, uri string, query url.Values, r io.Reader) (*http.Request, os.Error) {
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
    query.Set("access_token", accessToken)
    fullUrl := MakeUrl(uri, query)
    return http.NewRequest(method, fullUrl, r)
}

func (p *facebookClient) RetrieveUserInfo() (UserInfo, os.Error) {
    req, err := p.CreateAuthorizedRequest(_FACEBOOK_USERINFO_METHOD, nil, _FACEBOOK_USERINFO_URL, nil, nil)
    if err != nil {
        return nil, err
    }
    result := new(facebookUserInfoResult)
    resp, _, err := MakeRequest(p.client, req)
    if resp != nil && resp.Body != nil {
        if err2 := json.NewDecoder(resp.Body).Decode(&result); err == nil {
            err = err2
        }
    }
    return result, err
}

