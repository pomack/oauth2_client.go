include $(GOROOT)/src/Make.inc

TARG=github.com/pomack/oauth2_client
GOFILES=\
    facebook.go\
    google.go\
    linkedin.go\
    smugmug.go\
    twitter.go\
    yahoo.go\
    oauth1_client.go\
    oauth2_client.go\


include $(GOROOT)/src/Make.pkg
