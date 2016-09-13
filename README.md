[![Build Status](https://travis-ci.org/yageek/auth0.svg?branch=develop)](https://travis-ci.org/yageek/auth0)
[![Coverage Status](https://coveralls.io/repos/github/yageek/auth0/badge.svg?branch=develop)](https://coveralls.io/github/yageek/auth0?branch=develop)
[![GoDoc](https://godoc.org/github.com/yageek/auth0?status.png)](https://godoc.org/github.com/yageek/auth0)
[![Report Cart](http://goreportcard.com/badge/yageek/auth0)](http://goreportcard.com/report/yageek/auth0)
[![MIT License](http://img.shields.io/badge/license-MIT-blue.svg?style=flat)](LICENSE)

# auth0

auth0 is a package helping to authenticate using the [Auth0](https://auth0.com) service.

## Installation 

```
go get github.com/yageek/auth0
```

## Usage

```go
//Creates a configuration with the Auth0 information

secret, _ := base64.URLEncoding.DecodeString(os.Getenv("AUTH0_CLIENT_SECRET"))
audience := os.Getenv("AUTH0_CLIENT_ID")
issuer := "https://mydomain.eu.auth0.com/"

configuration := NewConfiguration(secret, audience, issuer, crypto.SigningMethodHS256)
validator := NewValidator(configuration)

token, err := validator.ValidateRequest(r)

if err != nil {
    fmt.Println("Token is not valid:", token)
}
```

## Example

### Gin

Using [Gin](https://github.com/gin-gonic/gin) and the [Auth0 Authorization Extension](https://auth0.com/docs/extensions/authorization-extension), you 
may want to implement the authentication auth like the following:

```go
// Access Control Helper function.
func shouldAccess(wantedGroups []string, groups []interface{}) bool { 
 /* Fill depending on your needs */
}

// Wrapping a Gin endpoint.
func RestrictToScope(handler gin.HandlerFunc, wantedGroups []string) gin.HandlerFunc {

	return gin.HandlerFunc(func(c *gin.Context) {

		jwt, err := validator.ValidateRequest(c.Request)

		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
			log.Println("Invalid tokem:", err)
			return
		}

		metadata, okMetadata := jwt.Claims().Get("app_metadata").(map[string]interface{})
		authorization, okAuthorization := metadata["authorization"].(map[string]interface{})
		groups, hasGroups := authorization["groups"].([]interface{})

		if !okMetadata || !okAuthorization || !hasGroups || !shouldAccess(wantedGroups, groups) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "need more privileges"})
			return
		}

		handler(c)
	})
}

// Use it
r.PUT("/news", auth.RestrictToScope(MyProtectedEndpoints, []string{auth.AdminGroup}))
```
