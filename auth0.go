package auth0

import (
	"github.com/SermoDigital/jose/crypto"
	"github.com/SermoDigital/jose/jws"
	"github.com/SermoDigital/jose/jwt"
	"net/http"
	"time"
)

// Configuration contains
// all the informations about the
// Auth0 service.
type Configuration struct {
	secret   []byte
	Audience string
	Issuer   string
	signIn   crypto.SigningMethod
	exp      time.Duration // EXPLeeway
	nbf      time.Duration // NBFLeeway
}

// NewConfiguration creates a configuration for server
func NewConfiguration(secret []byte, audience, issuer string, method crypto.SigningMethod) Configuration {
	return Configuration{
		secret:   secret,
		Audience: audience,
		Issuer:   issuer,
		signIn:   method,
		exp:      0,
		nbf:      0,
	}
}

// JWTValidator helps middleware
// to validate token
type JWTValidator struct {
	config    Configuration
	validator *jwt.Validator
	extractor RequestTokenExtractor
}

// NewValidator creates a new
// validator with the provided configuration.
func NewValidator(config Configuration) *JWTValidator {

	// Set expected claims
	expectedClaims := jws.Claims{}
	expectedClaims.SetIssuer(config.Issuer)
	expectedClaims.SetAudience(config.Audience)

	validator := jws.NewValidator(expectedClaims, config.exp, config.nbf, nil)

	return &JWTValidator{config, validator, RequestTokenExtractorFunc(FromRequest)}
}

func (v *JWTValidator) validateToken(token jwt.JWT) error {
	return token.Validate(v.config.secret, v.config.signIn, v.validator)
}

// ValidateRequest validates the token within
// the http request.
func (v *JWTValidator) ValidateRequest(r *http.Request) (jwt.JWT, error) {

	token, err := v.extractor.Extract(r)

	if err != nil {
		return nil, err
	}

	err = v.validateToken(token)
	return token, err
}
