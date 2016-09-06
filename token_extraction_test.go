package auth0

import (
	"fmt"
	"net/http"
	"testing"
)

var tokenRaw = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ"

func TestFromRequestExtraction(t *testing.T) {

	headerTokenRequest, _ := http.NewRequest("", "http://localhost", nil)
	headerValue := fmt.Sprintf("Bearer %s", tokenRaw)
	headerTokenRequest.Header.Add("Authorization", headerValue)

	_, err := FromRequest(headerTokenRequest)

	if err != nil {
		t.Error(err)
		t.FailNow()
	}

}
