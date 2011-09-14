package oauth2_client

type YahooClient struct {
    stdOAuth1Client
}

func NewYahooClient() *YahooClient {
    return &YahooClient{}
}

func (p *YahooClient) Initialize(properties Properties) {
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
    if v := properties.GetAsString("yahoo.oauth1.request_token_path.url"); len(v) > 0 {
        p.requestUrl = v
        //p.TemporaryCredentialRequestURI = v
    }
    if v := properties.GetAsString("yahoo.oauth1.request_token_path.method"); len(v) > 0 {
        p.requestUrlMethod = v
    }
    if v := properties.GetAsBool("yahoo.oauth1.request_token_path.protected"); true {
        p.requestUrlProtected = v
    }
    if v := properties.GetAsString("yahoo.oauth1.authorization_path.url"); len(v) > 0 {
        p.authorizationUrl = v
        //p.ResourceOwnerAuthorizationURI = v
    }
    if v := properties.GetAsString("yahoo.oauth1.access_token_path.url"); len(v) > 0 {
        p.accessUrl = v
        //p.TokenRequestURI = v
    }
    if v := properties.GetAsString("yahoo.oauth1.access_token_path.method"); len(v) > 0 {
        p.accessUrlMethod = v
    }
    if v := properties.GetAsBool("yahoo.oauth1.access_token_path.protected"); true {
        p.accessUrlProtected = v
    }
    if v := properties.GetAsBool("yahoo.oauth1.authorized_resource.protected"); true {
        p.authorizedResourceProtected = v
    }
    if v := properties.GetAsString("yahoo.oauth1.scope"); len(v) > 0 {
        //p.Scope = v
    }
}


