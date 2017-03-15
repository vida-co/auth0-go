package auth0

import (
	"errors"
	"fmt"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
	"net/http"
	"testing"
)

var secretProvider = NewKeyProvider([]byte("secret"))

func validConfiguration(configuration Configuration, tokenRaw string) error {
	validator := NewValidator(configuration)
	headerTokenRequest, _ := http.NewRequest("", "http://localhost", nil)
	headerValue := fmt.Sprintf("Bearer %s", tokenRaw)
	headerTokenRequest.Header.Add("Authorization", headerValue)

	_, err := validator.ValidateRequest(headerTokenRequest)
	return err
}

func TestValidatorFull(t *testing.T) {

	configuration := NewConfiguration(secretProvider, "audience", "issuer", jose.HS256)
	err := validConfiguration(configuration, tokenRaw)

	if err != nil {
		t.Error(err)
	}

	invalidToken := tokenRaw + `wefwefwef`
	err = validConfiguration(configuration, invalidToken)

	if err == nil {
		t.Error("Should be considered as invalid token")
	}
}
func TestValidatorEmpty(t *testing.T) {

	configuration := NewConfiguration(secretProvider, "", "", jose.HS256)
	validToken := `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ`

	err := validConfiguration(configuration, validToken)

	if err != nil {
		t.Error(err)
	}

	otherValidToken := `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJkcWRxd2Rxd2Rxd2RxIiwibmFtZSI6ImRxd2Rxd2Rxd2Rxd2Rxd2QiLCJhZG1pbiI6ZmFsc2V9.-MZNG6n5KtLIG4Tsa6oi25zZK5oadmrebS-1r1Ln82c`
	err = validConfiguration(configuration, otherValidToken)

	if err != nil {
		t.Error(err)
	}

}

func TestValidatorPartial(t *testing.T) {

	configuration := NewConfiguration(secretProvider, "required", "", jose.HS256)
	validToken := `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ`
	err := validConfiguration(configuration, validToken)

	if err == nil {
		t.Error("Should have failed")
	}
	otherValidToken := `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJkcWRxd2Rxd2Rxd2RxIiwibmFtZSI6ImRxd2Rxd2Rxd2Rxd2Rxd2QiLCJhZG1pbiI6ZmFsc2V9.-MZNG6n5KtLIG4Tsa6oi25zZK5oadmrebS-1r1Ln82c`
	err = validConfiguration(configuration, otherValidToken)

	if err == nil {
		t.Error("Should have failed")
	}
}

func invalidProvider(req *http.Request) (interface{}, error) {
	return nil, errors.New("simple error")
}
func TestInvalidProvider(t *testing.T) {

	provider := SecretProviderFunc(invalidProvider)
	configuration := NewConfiguration(provider, "required", "", jose.HS256)

	err := validConfiguration(configuration, tokenRaw)

	if err == nil {
		t.Error("Should failed")
	}
}

func TestClaims(t *testing.T) {

	configuration := NewConfiguration(secretProvider, "audience", "issuer", jose.HS256)
	validator := NewValidator(configuration)

	headerTokenRequest, _ := http.NewRequest("", "http://localhost", nil)
	headerValue := fmt.Sprintf("Bearer %s", tokenRaw)

	// Valid token
	headerTokenRequest.Header.Add("Authorization", headerValue)
	_, err := validator.ValidateRequest(headerTokenRequest)

	if err != nil {
		t.FailNow()
	}

	claims := map[string]interface{}{}
	tok, _ := jwt.ParseSigned(string(tokenRaw))

	err = validator.Claims(headerTokenRequest, tok, &claims)

	if err != nil {
		t.Error("Should have decode claims correctly")
	}

}
