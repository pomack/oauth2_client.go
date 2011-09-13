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

type AuthToken struct {
    Service     string
    Token       string
    Secret      string
}

type OAuth1Client struct {
    CurrentCredentials          OAuth1Credentials
    ServiceName                 string
    Realm                       string
    ConsumerKey                 string
    ConsumerSecret              string
    RequestUrl                  string
    AccessUrl                   string
    AuthorizationUrl            string
    CallbackUrl                 string
    RequestUrlMethod            string
    AccessUrlMethod             string
    RequestUrlProtected         bool
    AccessUrlProtected          bool
    AuthorizedResourceProtected bool
}


// Credentials represents client, temporary and token credentials.
type OAuth1Credentials struct {
	Token  string // Also known as consumer key or access token.
	Secret string // Also known as consumer secret or access token secret.
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

func (p *OAuth1Client) PrepareRequest(credentials *OAuth1Credentials, method, uri string, additional_params url.Values, timestamp *time.Time, nonce string) url.Values {
    if len(method) <= 0 {
        method = "GET"
    }
    params := make(url.Values)
    if len(p.Realm) > 0 {
        params.Set("realm", p.Realm)
    }
    params.Set("oauth_consumer_key", p.ConsumerKey)
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
    
    if credentials != nil && len(credentials.Token) > 0 {
        params.Set("oauth_token", credentials.Token)
    } else if len(p.CallbackUrl) > 0 {
        params.Set("oauth_callback", p.CallbackUrl)
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
    if credentials != nil && len(credentials.Secret) > 0 {
        secret = credentials.Secret
    }
    key := strings.Join([]string{p.ConsumerSecret, secret}, "&")
	h := hmac.NewSHA1([]byte(key))
	h.Write([]byte(message))
	sum := h.Sum()

	encodedSum := make([]byte, base64.StdEncoding.EncodedLen(len(sum)))
	base64.StdEncoding.Encode(encodedSum, sum)
    signature := strings.TrimSpace(string(encodedSum))
    params.Set("oauth_signature", signature)
    return params
}

func (p *OAuth1Client) GenerateRequest(credentials *OAuth1Credentials, headers http.Header, method, uri string, additional_params url.Values, protected bool) (*http.Request, os.Error) {
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
    v := p.PrepareRequest(credentials, method, uri, additional_params, nil, "")
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

func (p *OAuth1Client) MakeSyncRequest(credentials *OAuth1Credentials, headers http.Header, method, uri string, additional_params url.Values, protected bool) (*http.Response, os.Error) {
    req, err := p.GenerateRequest(credentials, headers, method, uri, additional_params, protected)
    if err != nil {
        return nil, err
    }
    return MakeRequest(req)
}

func (p *OAuth1Client) MakeAsyncRequest(req *http.Request, handler RequestHandler) {
    resp, err := MakeRequest(req)
    if handler != nil {
        handler(resp, err, req)
    }
}

func (p *OAuth1Client) extractCredentials(resp *http.Response) (*OAuth1Credentials, string, os.Error) {
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
    cred := new(OAuth1Credentials)
    if m != nil {
        cred.Token = m.Get("oauth_token")
        cred.Secret = m.Get("oauth_token_secret")
    }
    return cred, body, nil
}

func (p *OAuth1Client) GetAuthToken() (*OAuth1Credentials, os.Error) {
    resp, err := p.MakeSyncRequest(nil, nil, p.RequestUrlMethod, p.RequestUrl, nil, p.RequestUrlProtected)
    if err != nil {
        return nil, err
    }
    credentials, body, err := p.extractCredentials(resp)
    if credentials != nil && len(credentials.Token) > 0 && len(credentials.Secret) > 0 {
        if oauth1TokenSecretMap == nil {
            oauth1TokenSecretMap = make(map[string]string)
        }
        oauth1TokenSecretMap[credentials.Token] = credentials.Secret
    } else if err == nil && len(body) > 0 {
        err = os.NewError(body)
    }
    return credentials, err
}


func (p *OAuth1Client) RequestToken(client *http.Client, credentials *OAuth1Credentials, verifier string) (*OAuth1Credentials, string, os.Error) {
    if oauth1TokenSecretMap == nil {
        oauth1TokenSecretMap = make(map[string]string)
    }
    auth_token, _ := url.QueryUnescape(credentials.Token)
    auth_verifier, _ := url.QueryUnescape(verifier)
    
    auth_secret, _ := oauth1TokenSecretMap[auth_token]
    if len(auth_secret) <= 0 && len(credentials.Secret) > 0 {
        auth_secret = credentials.Secret
    }
    log.Print("Using auth_token: ", auth_token, ", auth_secret: ", auth_secret, ", oauth_verifier: ", auth_verifier)
    cred := &OAuth1Credentials{Token:auth_token, Secret:auth_secret}
    additional_params := make(url.Values)
    additional_params.Set("oauth_verifier", auth_verifier)
    resp, err := p.MakeSyncRequest(cred, nil, p.AccessUrlMethod, p.AccessUrl, additional_params, p.AccessUrlProtected)
    c, body, err2 := p.extractCredentials(resp)
    if c != nil && len(c.Token) > 0 && len(c.Secret) > 0 {
        oauth1TokenSecretMap[c.Token] = c.Secret
    } else if err2 == nil && len(body) > 0 {
        err2 = os.NewError(body)
    }
    if err == nil {
        err = err2
    }
    return c, body, err
}


// AuthorizationURL returns the full authorization URL.
func (c *OAuth1Client) AuthorizationURL(temporaryCredentials *OAuth1Credentials) string {
	return c.AuthorizationUrl + "?oauth_token=" + string(oauthEncode(temporaryCredentials.Token))
}


func (p *OAuth1Client) GenerateRequestTokenUrl(properties Properties) string {
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

func (p *OAuth1Client) RequestTokenGranted(req *http.Request) bool {
    if req == nil {
        return false
    }
    q := req.URL.Query()
    token := q.Get("oauth_token")
    verifier := q.Get("oauth_verifier")
    if len(token) <= 0 || len(verifier) <= 0 {
        return false
    }
    tempCredentials := &OAuth1Credentials{Token:token}
    newCredentials, _, err := p.RequestToken(nil, tempCredentials, verifier)
    if err != nil || newCredentials == nil {
        return false
    }
    p.CurrentCredentials = *newCredentials
    return true
}

func (p *OAuth1Client) ExchangeRequestTokenForAccess(req *http.Request) os.Error {
    if req == nil {
        return os.NewError("Request cannot be nil")
    }
    q := req.URL.Query()
    token := q.Get("oauth_token")
    verifier := q.Get("oauth_verifier")
    if len(token) <= 0 || len(verifier) <= 0 {
        return os.NewError("Expected both oauth_token and oauth_verifier")
    }
    tempCredentials := &OAuth1Credentials{Token:token}
    newCredentials, body, err := p.RequestToken(nil, tempCredentials, verifier)
    if err != nil {
        return err
    }
    if newCredentials != nil && len(newCredentials.Token) > 0 && len(newCredentials.Secret) > 0 {
        log.Print("Setting current credentials to: ", newCredentials)
        p.CurrentCredentials = *newCredentials
    } else if len(body) > 0 {
        return os.NewError(body)
    }
    return nil
}

func (p *OAuth1Client) CreateAuthorizedRequest(method string, headers http.Header, uri string, query url.Values, r io.Reader) (*http.Request, os.Error) {
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
    return p.GenerateRequest(&p.CurrentCredentials, headers, method, uri, query, p.AuthorizedResourceProtected)
}


