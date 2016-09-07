[![Build Status](https://travis-ci.org/yageek/auth0.svg?branch=develop)](https://travis-ci.org/yageek/auth0)
[![Coverage Status](https://coveralls.io/repos/github/yageek/auth0/badge.svg?branch=develop)](https://coveralls.io/github/yageek/auth0?branch=develop)
[![GoDoc](https://godoc.org/github.com/yageek/auth0?status.png)](https://godoc.org/github.com/yageek/auth0)
[![MIT License](http://img.shields.io/badge/license-MIT-blue.svg?style=flat)](LICENSE)

# auth0

auth0 is a package helping to authenticate against [auth0](https://auth0.com) services.

## Installation 

```
go get github.com/yageek/auth0
```

## Usage

```go
    //Creates a configuration with the Auth0 information
    secret, _ := base64.URLEncoding.DecodeString(os.Getenv("AUTH0_CLIENT_SECRET"))
    audience := os.Getenv("AUTH0_CLIENT_ID")

    configuration := NewConfiguration(secret, audience, "https://mydomain.eu.auth0.com/", crypto.SigningMethodHS256)
	validator := NewValidator(configuration)

    token, err := validator.ValidateRequest(r)
    
    if err != nil {
        fmt.Println("Token is not valid:", token)
    }
```
