package oauth2_client

import (
    "sync"
)

const (
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"
    
    GOOGLE_SCOPE_FEEDS = "https://www.google.com/m8/feeds/"
    
    GOOGLE_DATETIME_FORMAT = "2006-01-02T15:04:05.000Z"
    FACEBOOK_DATETIME_FORMAT = "2006-01-02T15:04:05-0700"
    YAHOO_DATETIME_FORMAT = "2006-01-02T15:04:05Z"
    
    _GOOGLE_ACCESS_TOKEN_URL = "https://accounts.google.com/o/oauth2/auth"
    _GOOGLE_ACCESS_TOKEN_METHOD = "GET"
    _GOOGLE_AUTHORIZATION_CODE_URL = "https://accounts.google.com/o/oauth2/token"
    _GOOGLE_AUTHORIZATION_CODE_METHOD = "POST"
    _GOOGLE_REFRESH_TOKEN_URL = "https://accounts.google.com/o/oauth2/token"
    _GOOGLE_REFRESH_TOKEN_METHOD = "POST"
    _GOOGLE_USERINFO_URL = "https://www.google.com/m8/feeds/contacts/default/full/?alt=json&max-results=0"
    _GOOGLE_USERINFO_METHOD = "GET"
    _GOOGLE_USERINFO_FEED_REL = "http://schemas.google.com/g/2005#feed"
    
    _FACEBOOK_ACCESS_TOKEN_URL = "https://www.facebook.com/dialog/oauth"
    _FACEBOOK_ACCESS_TOKEN_METHOD = "GET"
    _FACEBOOK_AUTHORIZATION_CODE_URL = "https://graph.facebook.com/oauth/access_token"
    _FACEBOOK_AUTHORIZATION_CODE_METHOD = "POST"
    _FACEBOOK_REFRESH_TOKEN_URL = "https://graph.facebook.com/oauth/access_token"
    _FACEBOOK_REFRESH_TOKEN_METHOD = "POST"
    _FACEBOOK_USERINFO_URL = "https://graph.facebook.com/me"
    _FACEBOOK_USERINFO_METHOD = "GET"
    
    _TWITTER_REQUEST_TOKEN_URL = "http://api.twitter.com/oauth/request_token"
    _TWITTER_REQUEST_TOKEN_METHOD = "POST"
    _TWITTER_REQUEST_TOKEN_PROTECTED = false
    _TWITTER_ACCESS_TOKEN_URL = "https://api.twitter.com/oauth/access_token"
    _TWITTER_ACCESS_TOKEN_METHOD = "POST"
    _TWITTER_ACCESS_TOKEN_PROTECTED = true
    _TWITTER_AUTHORIZATION_PATH_URL = "https://api.twitter.com/oauth/authorize"
    _TWITTER_AUTHORIZED_RESOURCE_PROTECTED = true
    _TWITTER_USERINFO_URL = "http://api.twitter.com/1/account/verify_credentials.json"
    _TWITTER_USERINFO_METHOD = "GET"
    
    _LINKEDIN_REQUEST_TOKEN_URL = "https://api.linkedin.com/uas/oauth/requestToken"
    _LINKEDIN_REQUEST_TOKEN_METHOD = "GET"
    _LINKEDIN_REQUEST_TOKEN_PROTECTED = false
    _LINKEDIN_ACCESS_TOKEN_URL = "https://api.linkedin.com/uas/oauth/accessToken"
    _LINKEDIN_ACCESS_TOKEN_METHOD = "GET"
    _LINKEDIN_ACCESS_TOKEN_PROTECTED = true
    _LINKEDIN_AUTHORIZATION_PATH_URL = "https://www.linkedin.com/uas/oauth/authorize"
    _LINKEDIN_AUTHORIZED_RESOURCE_PROTECTED = true
    _LINKEDIN_USERINFO_URL = "http://api.linkedin.com/v1/people/~:(id,first-name,last-name,headline,location,num-connections,num-connections-capped,summary,twitter-accounts,date-of-birth,picture-url,public-profile-url,api-standard-profile-request,member-url-resources,im-accounts,phone-numbers)"
    _LINKEDIN_USERINFO_METHOD = "GET"
    
    _YAHOO_REQUEST_TOKEN_URL = "https://api.login.yahoo.com/oauth/v2/get_request_token"
    _YAHOO_REQUEST_TOKEN_METHOD = "GET"
    _YAHOO_REQUEST_TOKEN_PROTECTED = false
    _YAHOO_ACCESS_TOKEN_URL = "https://api.login.yahoo.com/oauth/v2/get_token"
    _YAHOO_ACCESS_TOKEN_METHOD = "GET"
    _YAHOO_ACCESS_TOKEN_PROTECTED = false
    _YAHOO_AUTHORIZATION_PATH_URL = "https://api.login.yahoo.com/oauth/v2/request_auth"
    _YAHOO_AUTHORIZED_RESOURCE_PROTECTED = true
    _YAHOO_USERINFO_URL = "http://social.yahooapis.com/v1/user/PIPEKBTH7CDQT5PV55TUXBBDMU/profile?format=json"
    _YAHOO_USERINFO_METHOD = "GET"
    
    _SMUGMUG_REQUEST_TOKEN_URL = "http://api.smugmug.com/services/oauth/getRequestToken.mg"
    _SMUGMUG_REQUEST_TOKEN_METHOD = "GET"
    _SMUGMUG_REQUEST_TOKEN_PROTECTED = false
    _SMUGMUG_ACCESS_TOKEN_URL = "http://api.smugmug.com/services/oauth/getAccessToken.mg"
    _SMUGMUG_ACCESS_TOKEN_METHOD = "GET"
    _SMUGMUG_ACCESS_TOKEN_PROTECTED = false
    _SMUGMUG_AUTHORIZATION_PATH_URL = "http://api.smugmug.com/services/oauth/authorize.mg"
    _SMUGMUG_AUTHORIZED_RESOURCE_PROTECTED = true
    _SMUGMUG_USERINFO_URL = "https://secure.smugmug.com/services/api/json/1.3.0/?method=smugmug.auth.checkAccessToken"
    _SMUGMUG_USERINFO_METHOD = "GET"
    
)

var (
	nonceLock               sync.Mutex
	nonceCounter            uint64
	oauth1TokenSecretMap    map[string]*oauth1SecretInfo
	EnableLogHttpRequests   = false
	EnableLogHttpResponses  = false
	EnableLogDebug          = false
	EnableLogInfo           = false
	EnableLogError          = true
)

