package auth0

import (
	"time"
	"gopkg.in/square/go-jose.v2/jwt"
	"net/http"
	"gopkg.in/square/go-jose.v2"
)

type SecretProvider interface {
	GetSecret(req *http.Request) (interface{}, error)
}

type SecretProviderFunc func (req *http.Request) (interface{}, error)

func (f SecretProviderFunc) GetSecret(req *http.Request) (interface{}, error) {
	return f(req)
}

func NewKeyProvider(key interface{}) SecretProvider {
	return SecretProviderFunc(func(req *http.Request) (interface{},error) {
		return key, nil
	})
}
// Configuration contains
// all the informations about the
// Auth0 service.
type Configuration struct {
	secretProvider   SecretProvider
	expectedClaims jwt.Expected
	signIn   jose.SignatureAlgorithm
	exp      time.Duration // EXPLeeway
	nbf      time.Duration // NBFLeeway
}

// NewConfiguration creates a configuration for server
func NewConfiguration(provider SecretProvider, audience, issuer string, method jose.SignatureAlgorithm) Configuration {
	var aud []string
	if audience != "" {
		aud = []string{audience}
	}

	return Configuration{
		secretProvider:   provider,
		expectedClaims: jwt.Expected{Issuer: issuer, Audience: aud},
		signIn:   method,
		exp:      0,
		nbf:      0,
	}
}

// JWTValidator helps middleware
// to validate token
type JWTValidator struct {
	config    Configuration
	extractor RequestTokenExtractor

}

// NewValidator creates a new
// validator with the provided configuration.
func NewValidator(config Configuration) *JWTValidator {
	return &JWTValidator{config, RequestTokenExtractorFunc(FromHeader)}
}

// ValidateRequest validates the token within
// the http request.
func (v *JWTValidator) ValidateRequest(r *http.Request) (*jwt.JSONWebToken, error) {

	token, err := v.extractor.Extract(r)

	if err != nil {
		return nil, err
	}

	claims := jwt.Claims{}
	key, err := v.config.secretProvider.GetSecret(r)
	if err != nil {
		return nil, err
	}

	err = token.Claims(key, &claims)

	if err != nil {
		return nil, err
	}

	err = claims.Validate(v.config.expectedClaims)
	return token, err
}
