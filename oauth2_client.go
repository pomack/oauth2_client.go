package oauth2_client

import (
    "bytes"
    "http"
    "io"
    "json"
    "log"
    "os"
    "strconv"
    "strings"
    "time"
    "url"
)

type Properties map[string]interface{}

func (p Properties) Set(key string, value interface{}) {
    p[key] = value
}

func (p Properties) Get(key string) interface{} {
    value, _ := p[key]
    return value
}

func (p Properties) GetAsString(key string) string {
    value, _ := p[key]
    switch v := value.(type) {
    case nil:
        return ""
    case string:
        return v
    case int:
        return strconv.Itoa(v)
    case int64:
        return strconv.Itoa64(v)
    case float64:
        return strconv.Ftoa64(v, 'g', -1)
    case bool:
        if v {
            return "true"
        }
        return "false"
    }
    bytes, _ := json.Marshal(value)
    return string(bytes)
}

func (p Properties) GetAsInt(key string) int {
    value, _ := p[key]
    switch v := value.(type) {
    case nil:
        return 0
    case int:
        return v
    case float64:
        return int(v)
    case int64:
        return int(v)
    case string:
        i, _ := strconv.Atoi(v)
        return i
    case bool:
        if v {
            return 1
        }
        return 0
    case Properties:
        return len(v)
    case []interface{}:
        return len(v)
    }
    return 0
}

func (p Properties) GetAsInt64(key string) int64 {
    value, _ := p[key]
    switch v := value.(type) {
    case nil:
        return 0
    case int:
        return int64(v)
    case float64:
        return int64(v)
    case int64:
        return v
    case string:
        i, _ := strconv.Atoi64(v)
        return i
    case bool:
        if v {
            return 1
        }
        return 0
    case Properties:
        return int64(len(v))
    case []interface{}:
        return int64(len(v))
    }
    return 0
}


func (p Properties) GetAsFloat64(key string) float64 {
    value, _ := p[key]
    switch v := value.(type) {
    case nil:
        return 0
    case int:
        return float64(v)
    case float64:
        return v
    case int64:
        return float64(v)
    case string:
        i, _ := strconv.Atof64(v)
        return i
    case bool:
        if v {
            return 1
        }
        return 0
    case Properties:
        return float64(len(v))
    case []interface{}:
        return float64(len(v))
    }
    return 0
}

func (p Properties) GetAsBool(key string) bool {
    value, _ := p[key]
    switch v := value.(type) {
    case nil:
        return false
    case bool:
        return v
    case int:
        return v != 0
    case float64:
        return v != 0.0
    case int64:
        return v != 0
    case string:
        s := strings.ToLower(v)
        return s == "true" || s == "1" || s == "yes"
    case Properties:
        return len(v) > 0
    case []interface{}:
        return len(v) > 0
    }
    return false
}

func (p Properties) GetAsObject(key string) Properties {
    value, _ := p[key]
    switch v := value.(type) {
    case nil, bool, int, float64, int64, string, []interface{}:
        return make(Properties)
    case Properties:
        return v
    case map[string]interface{}:
        return Properties(v)
    }
    return make(Properties)
}

func (p Properties) GetAsArray(key string) []interface{} {
    value, _ := p[key]
    switch v := value.(type) {
    case nil, bool, int, float64, int64, string, Properties:
        return make([]interface{}, 0)
    case []interface{}:
        return v
    }
    return make([]interface{}, 0)
}

func (p Properties) GetAsTime(key string, format string) *time.Time {
    value, _ := p[key]
    switch v := value.(type) {
    case nil, bool, []interface{}, Properties:
        return nil
    case string:
        t, _ := time.Parse(format, v)
        return t
    case int64:
        return time.SecondsToUTC(v)
    case int:
        return time.SecondsToUTC(int64(v))
    case float64:
        return time.SecondsToUTC(int64(v))
    }
    return nil
}

type UserInfo interface {
    Guid()          string
    Username()      string
    GivenName()     string
    FamilyName()    string
    DisplayName()   string
    Url()           string
}

type OAuth2Client interface {
    ServiceId() string
    Client() *http.Client
    Initialize(properties Properties)
    GenerateRequestTokenUrl(properties Properties) string
    RequestTokenGranted(req *http.Request) bool
    ExchangeRequestTokenForAccess(req *http.Request) os.Error
    CreateAuthorizedRequest(method string, headers http.Header, uri string, query url.Values, r io.Reader) (*http.Request, os.Error)
    RetrieveUserInfo()              (UserInfo, os.Error)
}

func AuthorizedGetRequest(client OAuth2Client, headers http.Header, uri string, query url.Values) (*http.Response, *http.Request, os.Error) {
    return AuthorizedRequest(client, "GET", headers, uri, query, nil)
}

func AuthorizedPostRequestString(client OAuth2Client, headers http.Header, uri string, query url.Values, data string) (*http.Response, *http.Request, os.Error) {
    return AuthorizedRequestBytes(client, "POST", headers, uri, query, []byte(data))
}

func AuthorizedPostRequestBytes(client OAuth2Client, headers http.Header, uri string, query url.Values, data []byte) (*http.Response, *http.Request, os.Error) {
    return AuthorizedRequestBytes(client, "POST", headers, uri, query, data)
}

func AuthorizedPostFormRequest(client OAuth2Client, headers http.Header, uri string, query url.Values, data url.Values) (*http.Response, *http.Request, os.Error) {
    if headers == nil {
        headers = make(http.Header)
    }
    var bytes []byte = nil
    if data != nil {
        bytes = []byte(data.Encode())
    }
    if v, ok := headers["Content-Type"]; !ok || len(v) <= 0 {
        headers.Set("Content-Type", "application/x-www-form-urlencoded")
    }
    return AuthorizedRequestBytes(client, "POST", headers, uri, query, bytes)
}

func AuthorizedPostRequest(client OAuth2Client, headers http.Header, uri string, query url.Values, r io.Reader) (*http.Response, *http.Request, os.Error) {
    return AuthorizedRequest(client, "POST", headers, uri, query, r)
}

func AuthorizedPutRequestString(client OAuth2Client, headers http.Header, uri string, query url.Values, data string) (*http.Response, *http.Request, os.Error) {
    return AuthorizedRequestBytes(client, "PUT", headers, uri, query, []byte(data))
}

func AuthorizedPutRequestBytes(client OAuth2Client, headers http.Header, uri string, query url.Values, data []byte) (*http.Response, *http.Request, os.Error) {
    return AuthorizedRequestBytes(client, "PUT", headers, uri, query, data)
}

func AuthorizedPutRequest(client OAuth2Client, headers http.Header, uri string, query url.Values, r io.Reader) (*http.Response, *http.Request, os.Error) {
    return AuthorizedRequest(client, "PUT", headers, uri, query, r)
}

func AuthorizedDeleteRequest(client OAuth2Client, headers http.Header, uri string, query url.Values) (*http.Response, *http.Request, os.Error) {
    return AuthorizedRequest(client, "DELETE", headers, uri, query, nil)
}

func AuthorizedRequestBytes(client OAuth2Client, method string, headers http.Header, uri string, query url.Values, data []byte) (*http.Response, *http.Request, os.Error) {
    var r io.Reader = nil
    if data != nil && len(data) > 0 {
        r = bytes.NewBuffer(data)
    }
    return AuthorizedRequest(client, method, headers, uri, query, r)
}

func AuthorizedRequest(client OAuth2Client, method string, headers http.Header, uri string, query url.Values, r io.Reader) (*http.Response, *http.Request, os.Error) {
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
    if strings.Contains(uri, "?") {
        parsedUrl, err := url.Parse(uri)
        if err != nil {
            return nil, nil, err
        }
        if len(parsedUrl.Scheme) > 0 && len(parsedUrl.RawAuthority) > 0 {
            uri = parsedUrl.Scheme + "://" + parsedUrl.RawAuthority + parsedUrl.Path
        } else {
            uri = parsedUrl.Path
        }
        for k, arr := range parsedUrl.Query() {
            for _, v := range arr {
                query.Add(k, v)
            }
        }
    }
    req, err := client.CreateAuthorizedRequest(method, headers, uri, query, r)
    if err != nil {
        return nil, req, err
    }
    return makeRequest(client.Client(), req)
}

func splitUrl(uri string, query url.Values) (string, url.Values) {
    parts := strings.SplitN(uri, "?", 1)
    if query == nil {
        query = make(url.Values)
    }
    if len(parts) > 1 && len(parts[1]) > 0 {
        queryPart := strings.Replace(parts[1], "?", "&", -1)
        m, _ := url.ParseQuery(queryPart)
        if m != nil {
            for k, arr := range m {
                for _, v := range arr {
                    query.Add(k, v)
                }
            }
        }
    }
    return parts[0], query
}

func makeUrl(uri string, query url.Values) string {
    var fullUri string
    if len(query) > 0 {
        if strings.Contains(uri, "?") {
            fullUri = uri + "&" + query.Encode()
        } else {
            fullUri = uri + "?" + query.Encode()
        }
    } else {
        fullUri = uri
    }
    return fullUri
}

func makeRequest(client *http.Client, req *http.Request) (*http.Response, *http.Request, os.Error) {
    if client == nil {
        client = new(http.Client)
    }
    dump, _ := http.DumpRequest(req, true)
    log.Print("Making Request:", "\n=================================\n", string(dump), "=================================\n")
    resp, err := client.Do(req)
    dump2, _ := http.DumpResponse(resp, true)
    log.Print("Received Response:", "\n=================================\n", string(dump2), "=================================\n")
    return resp, req, err
}

