package auth0

import (
	"fmt"
	"net/http"
	"testing"
)

var tokenRaw = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJzdWJqZWN0IiwiaXNzIjoiaXNzdWVyIiwiYXVkIjoiYXVkaWVuY2UifQ.XjWtlyDjBoFDREk1WbvxriSdLve5jI7uyamzCiGdg9U"
var audience = "audience"
var issuer = "issuer"

func TestFromRequestExtraction(t *testing.T) {

	headerTokenRequest, _ := http.NewRequest("", "http://localhost", nil)
	headerValue := fmt.Sprintf("Bearer %s", tokenRaw)
	headerTokenRequest.Header.Add("Authorization", headerValue)

	token, err := FromRequest(headerTokenRequest)

	if err != nil {
		t.Error(err)
		return
	}

	tokenAudience, hasAudience := token.Claims().Audience()
	tokenIssuer, hasIssuer := token.Claims().Issuer()

	if !hasAudience || !hasIssuer {
		t.Error("Missing audience, issuer or subject")
		return
	}

	if tokenIssuer != issuer || tokenAudience[0] != audience {
		t.Error("Invalid issuer, audience or subject:", tokenIssuer, tokenAudience[0])
	}

}
