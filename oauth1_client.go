package oauth2_client

import (
    "bytes"
    "container/vector"
    "crypto/hmac"
    "crypto/rand"
    "encoding/binary"
    "encoding/base64"
    "fmt"
    "http"
    "io"
    "io/ioutil"
    "log"
    "os"
    "sort"
    "strconv"
    "strings"
    "sync"
    "time"
    "url"
)

// Credentials represents client, temporary and token credentials.
type AuthToken interface {
    // Also known as consumer key or access token.
    Token()         string
    // Also known as consumer secret or access token secret.
    Secret()        string
    SetToken(value string)
    SetSecret(value string)
}

type stdAuthToken struct {
    token       string
    secret      string
}

type OAuth1Client interface {
    CurrentCredentials()            AuthToken
    Realm()                         string
    ConsumerKey()                   string
    ConsumerSecret()                string
    RequestUrl()                    string
    AccessUrl()                     string
    AuthorizationUrl()              string
    CallbackUrl()                   string
    RequestUrlMethod()              string
    AccessUrlMethod()               string
    RequestUrlProtected()           bool
    AccessUrlProtected()            bool
    AuthorizedResourceProtected()   bool
    SetCurrentCredentials(value AuthToken)
}

type stdOAuth1Client struct {
    currentCredentials          AuthToken
    serviceName                 string
    realm                       string
    consumerKey                 string
    consumerSecret              string
    requestUrl                  string
    accessUrl                   string
    authorizationUrl            string
    callbackUrl                 string
    requestUrlMethod            string
    accessUrlMethod             string
    requestUrlProtected         bool
    accessUrlProtected          bool
    authorizedResourceProtected bool
}

type RequestHandler func(*http.Response, os.Error, *http.Request)

var (
	nonceLock               sync.Mutex
	nonceCounter            uint64
	oauth1TokenSecretMap    map[string]string
)

// nonce returns a unique string.
func newNonce() string {
	nonceLock.Lock()
	defer nonceLock.Unlock()
	if nonceCounter == 0 {
		binary.Read(rand.Reader, binary.BigEndian, &nonceCounter)
	}
	result := strconv.Uitob64(nonceCounter, 16)
	nonceCounter += 1
	return result
}


func oauthEncode(text string) string {
    return url.QueryEscape(text)
}

func getKeys(m url.Values) []string {
    arr := make([]string, len(m))
    i := 0
    for k, _ := range m {
        arr[i] = k
        i++
    }
    return arr
}

func getSortedKeys(m url.Values) []string {
    arr := getKeys(m)
    sort.Strings(arr)
    return arr
}


func (p *stdAuthToken) Token() string { return p.token }
func (p *stdAuthToken) Secret() string { return p.secret }
func (p *stdAuthToken) SetToken(value string) { p.token = value }
func (p *stdAuthToken) SetSecret(value string) { p.secret = value }

func (p *stdOAuth1Client) CurrentCredentials()            AuthToken { return p.currentCredentials }
func (p *stdOAuth1Client) Realm()                         string    { return p.realm }
func (p *stdOAuth1Client) ConsumerKey()                   string    { return p.consumerKey }
func (p *stdOAuth1Client) ConsumerSecret()                string    { return p.consumerSecret }
func (p *stdOAuth1Client) RequestUrl()                    string    { return p.requestUrl }
func (p *stdOAuth1Client) AccessUrl()                     string    { return p.accessUrl }
func (p *stdOAuth1Client) AuthorizationUrl()              string    { return p.authorizationUrl }
func (p *stdOAuth1Client) CallbackUrl()                   string    { return p.callbackUrl }
func (p *stdOAuth1Client) RequestUrlMethod()              string    { return p.requestUrlMethod }
func (p *stdOAuth1Client) AccessUrlMethod()               string    { return p.accessUrlMethod }
func (p *stdOAuth1Client) RequestUrlProtected()           bool      { return p.requestUrlProtected }
func (p *stdOAuth1Client) AccessUrlProtected()            bool      { return p.accessUrlProtected }
func (p *stdOAuth1Client) AuthorizedResourceProtected()   bool      { return p.authorizedResourceProtected }
func (p *stdOAuth1Client) SetCurrentCredentials(value AuthToken)    { p.currentCredentials = value }


func oauth1PrepareRequest(p OAuth1Client, credentials AuthToken, method, uri string, additional_params url.Values, timestamp *time.Time, nonce string) url.Values {
    if len(method) <= 0 {
        method = "GET"
    }
    params := make(url.Values)
    if len(p.Realm()) > 0 {
        params.Set("realm", p.Realm())
    }
    params.Set("oauth_consumer_key", p.ConsumerKey())
    params.Set("oauth_signature_method", "HMAC-SHA1")
    if timestamp == nil {
        timestamp = time.UTC()
    }
    params.Set("oauth_timestamp", strconv.Itoa64(timestamp.Seconds()))
    if len(nonce) <= 0 {
        nonce = newNonce()
    }
    params.Set("oauth_nonce", nonce)
    params.Set("oauth_version", "1.0")
    
    if credentials != nil && len(credentials.Token()) > 0 {
        params.Set("oauth_token", credentials.Token())
    } else if len(p.CallbackUrl()) > 0 {
        params.Set("oauth_callback", p.CallbackUrl())
    }
    if additional_params != nil && len(additional_params) > 0 {
        for k, arr := range additional_params {
            if len(arr) > 0 {
                params.Del(k)
                for _, v := range arr {
                    params.Add(k, v)
                }
            }
        }
    }
    params_arr := new(vector.StringVector)
    for _, k := range getSortedKeys(params) {
        arr := params[k]
        ek := oauthEncode(k)
        for _, v := range arr {
            params_arr.Push(strings.Join([]string{ek, oauthEncode(v)}, "="))
        }
    }
    params_str := strings.Join(*params_arr, "&")
    message := strings.Join([]string{method, oauthEncode(uri), oauthEncode(params_str)}, "&")
    secret := ""
    if credentials != nil && len(credentials.Secret()) > 0 {
        secret = credentials.Secret()
    }
    key := strings.Join([]string{p.ConsumerSecret(), secret}, "&")
	h := hmac.NewSHA1([]byte(key))
	h.Write([]byte(message))
	sum := h.Sum()

	encodedSum := make([]byte, base64.StdEncoding.EncodedLen(len(sum)))
	base64.StdEncoding.Encode(encodedSum, sum)
    signature := strings.TrimSpace(string(encodedSum))
    params.Set("oauth_signature", signature)
    return params
}

func oauth1GenerateRequest(p OAuth1Client, credentials AuthToken, headers http.Header, method, uri string, additional_params url.Values, protected bool) (*http.Request, os.Error) {
    if protected {
        if additional_params == nil {
            additional_params = make(url.Values)
        }
        //theurl, _ := url.Parse(uri)
        //if theurl != nil && len(theurl.Host) > 0 {
            //if strings.HasSuffix(theurl.Host, "yahooapis.com") {
            //    additional_params.Set("realm", "yahooapis.com")
            //} else {
            //    additional_params.Set("realm", theurl.Host)
        //    }
        //}
    }
    v := oauth1PrepareRequest(p, credentials, method, uri, additional_params, nil, "")
    var finalUri string
    var r io.Reader
    if protected {
        if headers == nil {
            headers = make(http.Header)
        }
        realm := v.Get("realm")
        oauth_nonce := v.Get("oauth_nonce")
        oauth_timestamp := v.Get("oauth_timestamp")
        oauth_version := v.Get("oauth_version")
        oauth_signature_method := v.Get("oauth_signature_method")
        oauth_consumer_key := v.Get("oauth_consumer_key")
        oauth_token := v.Get("oauth_token")
        oauth_signature := v.Get("oauth_signature")
        v.Del("realm")
        v.Del("oauth_nonce")
        v.Del("oauth_timestamp")
        v.Del("oauth_version")
        v.Del("oauth_signature_method")
        v.Del("oauth_consumer_key")
        v.Del("oauth_token")
        v.Del("oauth_signature")
        oauth_realm := ""
        if len(realm) > 0 {
            oauth_realm = fmt.Sprint("realm=\"", url.QueryEscape(realm),"\",")
        }
        headers.Set("Authorization", fmt.Sprintf(`OAuth %soauth_nonce="%s",oauth_timestamp="%s",oauth_version="%s",oauth_signature_method="%s",oauth_consumer_key="%s",oauth_token="%s",oauth_signature="%s"`, oauth_realm, url.QueryEscape(oauth_nonce), url.QueryEscape(oauth_timestamp), url.QueryEscape(oauth_version), url.QueryEscape(oauth_signature_method), url.QueryEscape(oauth_consumer_key), url.QueryEscape(oauth_token), url.QueryEscape(oauth_signature)))
    }
    if method == "GET" {
        if strings.Contains(uri, "?") {
            finalUri = uri + "&" + v.Encode()
        } else {
            finalUri = uri + "?" + v.Encode()
        }
        r = nil
    } else {
        r = bytes.NewBufferString(v.Encode())
        finalUri = uri
    }
    req, err := http.NewRequest(method, finalUri, r)
    if req != nil {
        req.Header = headers
    }
    return req, err
}

func OAuth1MakeSyncRequest(p OAuth1Client, credentials AuthToken, headers http.Header, method, uri string, additional_params url.Values, protected bool) (*http.Response, os.Error) {
    req, err := oauth1GenerateRequest(p, credentials, headers, method, uri, additional_params, protected)
    if err != nil {
        return nil, err
    }
    return makeRequest(req)
}

func MakeAsyncRequest(req *http.Request, handler RequestHandler) {
    resp, err := makeRequest(req)
    if handler != nil {
        handler(resp, err, req)
    }
}

func (p *stdOAuth1Client) extractCredentials(resp *http.Response) (AuthToken, string, os.Error) {
    if resp == nil {
        return nil, "", nil
    }
    body_bytes, err := ioutil.ReadAll(resp.Body)
    body := string(body_bytes)
    if err != nil {
        return nil, body, err
    }
    m, err := url.ParseQuery(string(body))
    if err != nil {
        return nil, body, err
    }
    var cred AuthToken
    if m != nil {
        cred = &stdAuthToken{token:m.Get("oauth_token"), secret:m.Get("oauth_token_secret")}
    }
    return cred, body, nil
}

func (p *stdOAuth1Client) GetAuthToken() (AuthToken, os.Error) {
    resp, err := OAuth1MakeSyncRequest(p, nil, nil, p.RequestUrlMethod(), p.RequestUrl(), nil, p.RequestUrlProtected())
    if err != nil {
        return nil, err
    }
    credentials, body, err := p.extractCredentials(resp)
    if credentials != nil && len(credentials.Token()) > 0 && len(credentials.Secret()) > 0 {
        if oauth1TokenSecretMap == nil {
            oauth1TokenSecretMap = make(map[string]string)
        }
        oauth1TokenSecretMap[credentials.Token()] = credentials.Secret()
    } else if err == nil && len(body) > 0 {
        err = os.NewError(body)
    }
    return credentials, err
}


func (p *stdOAuth1Client) RequestToken(client *http.Client, credentials AuthToken, verifier string) (AuthToken, string, os.Error) {
    if oauth1TokenSecretMap == nil {
        oauth1TokenSecretMap = make(map[string]string)
    }
    auth_token, _ := url.QueryUnescape(credentials.Token())
    auth_verifier, _ := url.QueryUnescape(verifier)
    
    auth_secret, _ := oauth1TokenSecretMap[auth_token]
    if len(auth_secret) <= 0 && len(credentials.Secret()) > 0 {
        auth_secret = credentials.Secret()
    }
    log.Print("Using auth_token: ", auth_token, ", auth_secret: ", auth_secret, ", oauth_verifier: ", auth_verifier)
    cred := &stdAuthToken{token:auth_token, secret:auth_secret}
    additional_params := make(url.Values)
    additional_params.Set("oauth_verifier", auth_verifier)
    resp, err := OAuth1MakeSyncRequest(p, cred, nil, p.AccessUrlMethod(), p.AccessUrl(), additional_params, p.AccessUrlProtected())
    c, body, err2 := p.extractCredentials(resp)
    if c != nil && len(c.Token()) > 0 && len(c.Secret()) > 0 {
        oauth1TokenSecretMap[c.Token()] = c.Secret()
    } else if err2 == nil && len(body) > 0 {
        err2 = os.NewError(body)
    }
    if err == nil {
        err = err2
    }
    return c, body, err
}


// AuthorizationURL returns the full authorization URL.
func (c *stdOAuth1Client) AuthorizationURL(temporaryCredentials AuthToken) string {
    authUrl := c.AuthorizationUrl()
    if strings.Contains(authUrl, "?") {
        return authUrl + "&oauth_token=" + string(oauthEncode(temporaryCredentials.Token()))
    }
	return authUrl + "?oauth_token=" + string(oauthEncode(temporaryCredentials.Token()))
}


func (p *stdOAuth1Client) GenerateRequestTokenUrl(properties Properties) string {
    if properties == nil {
        properties = make(Properties)
    }
    cred, err := p.GetAuthToken()
    log.Print("Received credentials: ", cred)
    log.Print("Received err: ", err)
    if cred == nil || err != nil {
        return ""
    }
    return p.AuthorizationURL(cred)
}

func (p *stdOAuth1Client) RequestTokenGranted(req *http.Request) bool {
    if req == nil {
        return false
    }
    q := req.URL.Query()
    token := q.Get("oauth_token")
    verifier := q.Get("oauth_verifier")
    if len(token) <= 0 || len(verifier) <= 0 {
        return false
    }
    tempCredentials := &stdAuthToken{token:token}
    newCredentials, _, err := p.RequestToken(nil, tempCredentials, verifier)
    if err != nil || newCredentials == nil {
        return false
    }
    p.SetCurrentCredentials(newCredentials)
    return true
}

func (p *stdOAuth1Client) ExchangeRequestTokenForAccess(req *http.Request) os.Error {
    if req == nil {
        return os.NewError("Request cannot be nil")
    }
    q := req.URL.Query()
    token := q.Get("oauth_token")
    verifier := q.Get("oauth_verifier")
    if len(token) <= 0 || len(verifier) <= 0 {
        return os.NewError("Expected both oauth_token and oauth_verifier")
    }
    tempCredentials := &stdAuthToken{token:token}
    newCredentials, body, err := p.RequestToken(nil, tempCredentials, verifier)
    if err != nil {
        return err
    }
    if newCredentials != nil && len(newCredentials.Token()) > 0 && len(newCredentials.Secret()) > 0 {
        log.Print("Setting current credentials to: ", newCredentials)
        p.SetCurrentCredentials(newCredentials)
    } else if len(body) > 0 {
        return os.NewError(body)
    }
    return nil
}

func (p *stdOAuth1Client) CreateAuthorizedRequest(method string, headers http.Header, uri string, query url.Values, r io.Reader) (*http.Request, os.Error) {
    if len(method) <= 0 {
        method = "GET"
    }
    method = strings.ToUpper(method)
    if headers == nil {
        headers = make(http.Header)
    }
    if query == nil {
        query = make(url.Values)
    }
    return oauth1GenerateRequest(p, p.CurrentCredentials(), headers, method, uri, query, p.AuthorizedResourceProtected())
}


