package auth0

import (
	"github.com/SermoDigital/jose/jws"
	"github.com/SermoDigital/jose/jwt"
	"net/http"
)

// RequestTokenExtractor can extract a JWT
// from a request.
type RequestTokenExtractor interface {
	Extract(r *http.Request) (jwt.JWT, error)
}

// RequestTokenExtractorFunc function conforming
// to the RequestTokenExtractor interface.
type RequestTokenExtractorFunc func(r *http.Request) (jwt.JWT, error)

// Extract calls f(r)
func (f RequestTokenExtractorFunc) Extract(r *http.Request) (jwt.JWT, error) {
	return f(r)
}

// FromRequest looks for the request in the
// authentication header or call ParseMultipartForm
// if not present.
func FromRequest(r *http.Request) (jwt.JWT, error) {
	return jws.ParseJWTFromRequest(r)
}
