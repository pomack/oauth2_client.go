package oauth2_client

type YahooClient struct {
    OAuth1Client
}

func NewYahooClient() *YahooClient {
    return &YahooClient{}
}

func (p *YahooClient) Initialize(properties Properties) {
    if properties == nil {
        return
    }
    if v := properties.GetAsString("yahoo.realm"); len(v) > 0 {
        p.Realm = v
    }
    if v := properties.GetAsString("yahoo.consumer.key"); len(v) > 0 {
        p.ConsumerKey = v
        //p.Credentials.Token = v
    }
    if v := properties.GetAsString("yahoo.consumer.secret"); len(v) > 0 {
        p.ConsumerSecret = v
        //p.Credentials.Secret = v
    }
    if v := properties.GetAsString("yahoo.client.redirect_uri"); len(v) > 0 {
        p.CallbackUrl = v
    }
    if v := properties.GetAsString("yahoo.oauth1.request_token_path.url"); len(v) > 0 {
        p.RequestUrl = v
        //p.TemporaryCredentialRequestURI = v
    }
    if v := properties.GetAsString("yahoo.oauth1.request_token_path.method"); len(v) > 0 {
        p.RequestUrlMethod = v
    }
    if v := properties.GetAsBool("yahoo.oauth1.request_token_path.protected"); true {
        p.RequestUrlProtected = v
    }
    if v := properties.GetAsString("yahoo.oauth1.authorization_path.url"); len(v) > 0 {
        p.AuthorizationUrl = v
        //p.ResourceOwnerAuthorizationURI = v
    }
    if v := properties.GetAsString("yahoo.oauth1.access_token_path.url"); len(v) > 0 {
        p.AccessUrl = v
        //p.TokenRequestURI = v
    }
    if v := properties.GetAsString("yahoo.oauth1.access_token_path.method"); len(v) > 0 {
        p.AccessUrlMethod = v
    }
    if v := properties.GetAsBool("yahoo.oauth1.access_token_path.protected"); true {
        p.AccessUrlProtected = v
    }
    if v := properties.GetAsBool("yahoo.oauth1.authorized_resource.protected"); true {
        p.AuthorizedResourceProtected = v
    }
    if v := properties.GetAsString("yahoo.oauth1.scope"); len(v) > 0 {
        //p.Scope = v
    }
}


