package auth0

import (
	"fmt"
	"net/http"
	"testing"
	"gopkg.in/square/go-jose.v2/jwt"
)

var tokenRaw = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJzdWJqZWN0IiwiaXNzIjoiaXNzdWVyIiwiYXVkIjoiYXVkaWVuY2UifQ.XjWtlyDjBoFDREk1WbvxriSdLve5jI7uyamzCiGdg9U"
var audience = "audience"
var issuer = "issuer"

func TestFromRequestExtraction(t *testing.T) {

	headerTokenRequest, _ := http.NewRequest("", "http://localhost", nil)
	headerValue := fmt.Sprintf("Bearer %s", tokenRaw)
	headerTokenRequest.Header.Add("Authorization", headerValue)

	token, err := FromHeader(headerTokenRequest)

	if err != nil {
		t.Error(err)
		return
	}

	claims := jwt.Claims{}
	err = token.Claims([]byte("secret"), &claims)
	if err != nil {
		t.Error("Invalid Claims")
		t.FailNow()
	}


	if len(claims.Audience) != 1 || claims.Issuer == "" {
		t.Error("Missing audience, issuer or subject")
		return
	}

	if claims.Issuer != issuer || claims.Audience[0] != audience {
		t.Error("Invalid issuer, audience or subject:", claims.Issuer, claims.Audience[0])
	}

}
