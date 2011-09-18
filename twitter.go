package oauth2_client

import (
    "github.com/pomack/jsonhelper"
    "http"
    "json"
    "log"
    "os"
    "strings"
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

type TwitterUserInfoResult interface {
    UserInfo
    Id()                        string
    Name()                      string
    ScreenName()                string
    Location()                  string
    Lang()                      string
    Description()               string
    ProfileImageUrl()           string
    ProfileBackgroundImageUrl() string
    FavoritesCount()            int
    FriendsCount()              int
    FollowersCount()            int
    StatusesCount()             int
    TimeZone()                  string
    UtcOffset()                 int
    Following()                 bool
}

type twitterUserInfoResult struct {
    id                          string  `json:"id"`
    name                        string  `json:"name"`
    screenName                  string  `json:"screen_name"`
    url                         string  `json:"url"`
    location                    string  `json:"location"`
    lang                        string  `json:"lang"`
    description                 string  `json:"description"`
    profileImageUrl             string  `json:"profile_image_url"`
    profileBackgroundImageUrl   string  `json:"profile_background_image_url"`
    favoritesCount              int     `json:"favorites_count"`
    friendsCount                int     `json:"friends_count"`
    followersCount              int     `json:"followers_count"`
    statusesCount               int     `json:"status_count"`
    timeZone                    string  `json:"time_zone"`
    utcOffset                   int     `json:"utc_offset"`
    following                   bool    `json:"following"`
}


func (p *twitterUserInfoResult) Guid() string { return p.id }
func (p *twitterUserInfoResult) Username() string { return p.screenName }
func (p *twitterUserInfoResult) GivenName() string {
    parts := strings.SplitN(p.name, " ", 2)
    return parts[0]
}
func (p *twitterUserInfoResult) FamilyName() string {
    parts := strings.Split(p.name, " ")
    return parts[len(parts)-1]
}
func (p *twitterUserInfoResult) DisplayName() string { return p.name }
func (p *twitterUserInfoResult) Id() string { return p.id }
func (p *twitterUserInfoResult) Name() string { return p.name }
func (p *twitterUserInfoResult) ScreenName() string { return p.screenName }
func (p *twitterUserInfoResult) Url() string { return p.url }
func (p *twitterUserInfoResult) Location() string { return p.location }
func (p *twitterUserInfoResult) Lang() string { return p.lang }
func (p *twitterUserInfoResult) Description() string { return p.description }
func (p *twitterUserInfoResult) ProfileImageUrl() string { return p.profileImageUrl }
func (p *twitterUserInfoResult) ProfileBackgroundImageUrl() string { return p.profileBackgroundImageUrl }
func (p *twitterUserInfoResult) FavoritesCount() int { return p.favoritesCount }
func (p *twitterUserInfoResult) FriendsCount() int { return p.friendsCount }
func (p *twitterUserInfoResult) FollowersCount() int { return p.followersCount }
func (p *twitterUserInfoResult) StatusesCount() int { return p.statusesCount }
func (p *twitterUserInfoResult) TimeZone() string { return p.timeZone }
func (p *twitterUserInfoResult) UtcOffset() int { return p.utcOffset }
func (p *twitterUserInfoResult) Following() bool { return p.following }
func (p *twitterUserInfoResult) FromJSON(props jsonhelper.JSONObject) {
    p.id = props.GetAsString("id")
    p.name = props.GetAsString("name")
    p.screenName = props.GetAsString("screen_name")
    p.url = props.GetAsString("url")
    p.location = props.GetAsString("location")
    p.lang = props.GetAsString("lang")
    p.description = props.GetAsString("description")
    p.profileImageUrl = props.GetAsString("profile_image_url")
    p.profileBackgroundImageUrl = props.GetAsString("profile_background_image_url")
    p.favoritesCount = props.GetAsInt("favorites_count")
    p.friendsCount = props.GetAsInt("friends_count")
    p.followersCount = props.GetAsInt("followers_count")
    p.statusesCount = props.GetAsInt("statuses_count")
    p.timeZone = props.GetAsString("time_zone")
    p.utcOffset = props.GetAsInt("utc_offset")
    p.following = props.GetAsBool("following")
}

type twitterClient struct {
    stdOAuth1Client
}

func NewTwitterClient() OAuth2Client {
    return &twitterClient{}
}

func (p *twitterClient) RequestUrl() string { return _TWITTER_REQUEST_TOKEN_URL }
func (p *twitterClient) RequestUrlMethod() string { return _TWITTER_REQUEST_TOKEN_METHOD }
func (p *twitterClient) RequestUrlProtected() bool { return _TWITTER_REQUEST_TOKEN_PROTECTED }
func (p *twitterClient) AccessUrl() string { return _TWITTER_ACCESS_TOKEN_URL }
func (p *twitterClient) AccessUrlMethod() string  { return _TWITTER_ACCESS_TOKEN_METHOD }
func (p *twitterClient) AccessUrlProtected() bool { return _TWITTER_ACCESS_TOKEN_PROTECTED }
func (p *twitterClient) AuthorizationUrl() string { return _TWITTER_AUTHORIZATION_PATH_URL }
func (p *twitterClient) AuthorizedResourceProtected() bool { return _TWITTER_AUTHORIZED_RESOURCE_PROTECTED }
func (p *twitterClient) ServiceId() string { return "twitter.com" }
func (p *twitterClient) Initialize(properties jsonhelper.JSONObject) {
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
    if v := properties.GetAsString("twitter.oauth1.scope"); len(v) > 0 {
        //p.Scope = v
    }
}

func (p *twitterClient) GenerateRequestTokenUrl(properties jsonhelper.JSONObject) string {
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

func (p *twitterClient) RetrieveUserInfo() (UserInfo, os.Error) {
    req, err := p.CreateAuthorizedRequest(_TWITTER_USERINFO_METHOD, nil, _TWITTER_USERINFO_URL, nil, nil)
    if err != nil {
        return nil, err
    }
    result := new(twitterUserInfoResult)
    resp, _, err := makeRequest(p.client, req)
    if resp != nil && resp.Body != nil {
        props := jsonhelper.NewJSONObject()
        if err2 := json.NewDecoder(resp.Body).Decode(&props); err == nil {
            err = err2
        }
        result.FromJSON(props)
    }
    return result, err
}

