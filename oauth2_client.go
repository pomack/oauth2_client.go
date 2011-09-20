package oauth2_client

import (
    "github.com/pomack/jsonhelper"
    "bytes"
    "http"
    "io"
    "log"
    "os"
    "strings"
    "url"
)

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
    Initialize(properties jsonhelper.JSONObject)
    GenerateRequestTokenUrl(properties jsonhelper.JSONObject) string
    RequestTokenGranted(req *http.Request) bool
    ExchangeRequestTokenForAccess(req *http.Request) os.Error
    CreateAuthorizedRequest(method string, headers http.Header, uri string, query url.Values, r io.Reader) (*http.Request, os.Error)
    RetrieveUserInfo()              (UserInfo, os.Error)
}

func AuthorizedGetRequest(client OAuth2Client, headers http.Header, uri string, query url.Values) (*http.Response, *http.Request, os.Error) {
    return AuthorizedRequest(client, GET, headers, uri, query, nil)
}

func AuthorizedPostRequestString(client OAuth2Client, headers http.Header, uri string, query url.Values, data string) (*http.Response, *http.Request, os.Error) {
    return AuthorizedRequestBytes(client, POST, headers, uri, query, []byte(data))
}

func AuthorizedPostRequestBytes(client OAuth2Client, headers http.Header, uri string, query url.Values, data []byte) (*http.Response, *http.Request, os.Error) {
    return AuthorizedRequestBytes(client, POST, headers, uri, query, data)
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
    return AuthorizedRequestBytes(client, POST, headers, uri, query, bytes)
}

func AuthorizedPostRequest(client OAuth2Client, headers http.Header, uri string, query url.Values, r io.Reader) (*http.Response, *http.Request, os.Error) {
    return AuthorizedRequest(client, POST, headers, uri, query, r)
}

func AuthorizedPutRequestString(client OAuth2Client, headers http.Header, uri string, query url.Values, data string) (*http.Response, *http.Request, os.Error) {
    return AuthorizedRequestBytes(client, PUT, headers, uri, query, []byte(data))
}

func AuthorizedPutRequestBytes(client OAuth2Client, headers http.Header, uri string, query url.Values, data []byte) (*http.Response, *http.Request, os.Error) {
    return AuthorizedRequestBytes(client, PUT, headers, uri, query, data)
}

func AuthorizedPutRequest(client OAuth2Client, headers http.Header, uri string, query url.Values, r io.Reader) (*http.Response, *http.Request, os.Error) {
    return AuthorizedRequest(client, PUT, headers, uri, query, r)
}

func AuthorizedDeleteRequest(client OAuth2Client, headers http.Header, uri string, query url.Values) (*http.Response, *http.Request, os.Error) {
    return AuthorizedRequest(client, DELETE, headers, uri, query, nil)
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
        method = GET
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
    return MakeRequest(client.Client(), req)
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

func MakeUrl(uri string, query url.Values) string {
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

func MakeRequest(client *http.Client, req *http.Request) (*http.Response, *http.Request, os.Error) {
    if client == nil {
        client = new(http.Client)
    }
    dump, _ := http.DumpRequest(req, true)
    if EnableLogHttpRequests {
        log.Print("Making Request:", "\n=================================\n", string(dump), "=================================\n")
    }
    resp, err := client.Do(req)
    dump2, _ := http.DumpResponse(resp, true)
    if EnableLogHttpResponses {
        log.Print("Received Response:", "\n=================================\n", string(dump2), "=================================\n")
    }
    return resp, req, err
}

