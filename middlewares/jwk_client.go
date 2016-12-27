package middlewares

import (
	"sync"
	"net/url"
)
type JWKClientOptions struct{
	UseCache bool
	RateLimit int
	URI url.URL
}

var DefaultOptions = JWKClientOptions{true, 3}

type JWKClient struct {
	keys map[string]interface{}
	mu   sync.Mutex
}

func NewJWKClient(options JWKClientOptions) (*JWKClient, error){
	return &JWKClient{keys: map[string]interface{}{}}
}


func (j *JWKClient) downloadKeys() {

}
func (j *JWKClient) addKey(ID string, key interface{}) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.keys[ID] = key
}

func (j *JWKClient) getKey(ID string) {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.keys[ID]

}

func (j *JWKClient) deleteKey(ID string) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if _, ok := j.keys[ID]; ok {
		delete(j.keys,ID)
	}
}
