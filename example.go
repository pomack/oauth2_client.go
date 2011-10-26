package main
import (
   "github.com/pomack/jsonhelper.go/jsonhelper"
   "github.com/pomack/oauth2_client.go/oauth2_client"
   "http"
   "io"
   "json"
   "log"
)

const (
    GOOGLE_SETTINGS_STRING = `{
        "google.client.id" : "yourclientid.apps.googleusercontent.com",
        "google.client.secret" : "yourpassword",
        "google.client.redirect_uri" : "http://localhost:8000/auth/oauth2/oauth2callback/",
        "google.client.scope" : "https://www.google.com/m8/feeds/"
       }`
    GOOGLE_CONTACTS_TEST_URL = "https://www.google.com/m8/feeds/contacts/default/full?alt=json&max-results=1"
)


var (
    settings jsonhelper.JSONObject
)

// setup some settings that you'll need to use the Google OAuth2 client
// You'll need to get your own API key
func init() {
   settingsMap := make(map[string]interface{})
   json.Unmarshal([]byte(GOOGLE_SETTINGS_STRING), &settingsMap)
   settings = jsonhelper.NewJSONObjectFromMap(settingsMap)
   //log.Printf("Settings: %#v", settings)
}


func HandleInitialClientRedirect(w http.ResponseWriter, req *http.Request) {
   client := oauth2_client.NewGoogleClient()
   client.Initialize(settings)
   tokenUrl := client.GenerateRequestTokenUrl(jsonhelper.NewJSONObject())
   if len(tokenUrl) > 0 {
       w.Header().Set("Location", tokenUrl)
       w.WriteHeader(302)
   } else {
       w.WriteHeader(500)
   }
}

func HandleSuccessfulLogin(w http.ResponseWriter, req *http.Request) {
   client := oauth2_client.NewGoogleClient()
   client.Initialize(settings)
   client.ExchangeRequestTokenForAccess(req)
   useReq, _ := client.CreateAuthorizedRequest("GET", nil, GOOGLE_CONTACTS_TEST_URL, nil, nil)
   resp, _, _ := oauth2_client.MakeRequest(client, useReq)
   h := w.Header()
   for k, v := range resp.Header {
       for _, v1 := range v {
           h.Add(k, v1)
       }
   }
   w.WriteHeader(resp.StatusCode)
   io.Copy(w, resp.Body)
}

func main() {
   http.HandleFunc("/", HandleInitialClientRedirect)
   http.HandleFunc("/auth/oauth2/oauth2callback/", HandleSuccessfulLogin)
   log.Print("Open your browser and go to http://localhost:8080/\n")
   err := http.ListenAndServe(":8000", nil)
   if err != nil {
       log.Printf("ListenAndServe: ", err.String())
   }
}
