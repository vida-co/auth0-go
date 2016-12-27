package auth0

import (
	"fmt"
	"gopkg.in/square/go-jose.v2"
	"net/http"
	"testing"
)


var secretProvider = NewKeyProvider([]byte("secret"))

func TestValidatorFull(t *testing.T) {

	configuration := NewConfiguration(secretProvider, "audience", "issuer", jose.HS256)
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
func TestValidatorEmpty(t *testing.T) {

	configuration := NewConfiguration(secretProvider, "", "", jose.HS256)
	validator := NewValidator(configuration)
	headerTokenRequest, _ := http.NewRequest("", "http://localhost", nil)
	validToken := `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ`
	headerValue := fmt.Sprintf("Bearer %s", validToken)

	headerTokenRequest.Header.Set("Authorization", headerValue)
	_, err := validator.ValidateRequest(headerTokenRequest)

	if err != nil {
		t.Error(err)
	}
	// Invalid token
	// Default JWT.io token
	otherValidToken := `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJkcWRxd2Rxd2Rxd2RxIiwibmFtZSI6ImRxd2Rxd2Rxd2Rxd2Rxd2QiLCJhZG1pbiI6ZmFsc2V9.-MZNG6n5KtLIG4Tsa6oi25zZK5oadmrebS-1r1Ln82c`
	headerValue = fmt.Sprintf("Bearer %s", otherValidToken)
	headerTokenRequest.Header.Set("Authorization", headerValue)

	_, err = validator.ValidateRequest(headerTokenRequest)

	if err != nil {
		t.Error(err)
	}

}

func TestValidatorPartial(t *testing.T) {

	configuration := NewConfiguration(secretProvider, "required", "", jose.HS256)
	validator := NewValidator(configuration)
	headerTokenRequest, _ := http.NewRequest("", "http://localhost", nil)
	validToken := `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ`
	headerValue := fmt.Sprintf("Bearer %s", validToken)

	headerTokenRequest.Header.Set("Authorization", headerValue)
	_, err := validator.ValidateRequest(headerTokenRequest)

	if err == nil {
		t.Error("Should have failed")
	}
	// Invalid token
	// Default JWT.io token
	otherValidToken := `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJkcWRxd2Rxd2Rxd2RxIiwibmFtZSI6ImRxd2Rxd2Rxd2Rxd2Rxd2QiLCJhZG1pbiI6ZmFsc2V9.-MZNG6n5KtLIG4Tsa6oi25zZK5oadmrebS-1r1Ln82c`
	headerValue = fmt.Sprintf("Bearer %s", otherValidToken)
	headerTokenRequest.Header.Set("Authorization", headerValue)

	_, err = validator.ValidateRequest(headerTokenRequest)

	if err == nil {
		t.Error("Should have failed")
	}

}
