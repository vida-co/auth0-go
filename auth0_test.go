package auth0

import (
	"fmt"
	"github.com/SermoDigital/jose/crypto"
	"net/http"
	"testing"
)

func TestValidator(t *testing.T) {

	configuration := NewConfiguration([]byte("secret"), "audience", "issuer", crypto.SigningMethodHS256)
	validator := NewValidator(configuration)
	headerTokenRequest, _ := http.NewRequest("", "http://localhost", nil)
	headerValue := fmt.Sprintf("Bearer %s", tokenRaw)

	// Valid token
	headerTokenRequest.Header.Add("Authorization", headerValue)

	_, err := validator.ValidateRequest(headerTokenRequest)

	if err != nil {
		t.Error(err)
	}

	// Invalid token
	// Default JWT.io token
	invalidToken := `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJzdWJqZWN0IiwiaXNzIjoiaXNzdWVyIiwiYXVkIjoiYXVkaWVuY2UifQ.XjWtlyDjBoFDREk1WbvxriSdLve5jI7uyamzCiGdg9U`
	headerTokenRequest.Header.Set("Authorization", invalidToken)

	_, err = validator.ValidateRequest(headerTokenRequest)

	if err == nil {
		t.Error("Should be considered as invalid token")
	}
}
