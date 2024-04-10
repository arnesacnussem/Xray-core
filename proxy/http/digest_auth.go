package http

// https://github.com/golang/go/issues/29409
// https://github.com/delphinus/go-digest-request/blob/master/digestRequest.go

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"strings"
	"time"
)

type DigestAuth struct {
	username   string
	password   string
	nonceCount nonceCount
	parts      map[string]string
	ha1        string
	HasSetup   bool
}

const nonce = "nonce"
const qop = "qop"
const realm = "realm"
const proxyAuthenticate = "Proxy-Authenticate"
const proxyAuthorization = "Proxy-Authorization"

var digestAuthHeadersWanted = []string{nonce, qop, realm}

func (r *DigestAuth) getNonceCount() string {
	r.nonceCount++
	return r.nonceCount.String()
}

func (r *DigestAuth) setup(resp *http.Response) error {
	headers := strings.Split(resp.Header[proxyAuthenticate][0], ",")
	parts := make(map[string]string, len(digestAuthHeadersWanted))
	for _, r := range headers {
		for _, w := range digestAuthHeadersWanted {
			if strings.Contains(r, w) {
				parts[w] = strings.Split(r, `"`)[1]
			}
		}
	}

	if len(parts) != len(digestAuthHeadersWanted) {
		return fmt.Errorf("header is invalid: %+v", parts)
	}

	r.parts = parts
	r.ha1 = getMD5([]string{r.username, parts[realm], r.password})
	r.HasSetup = true
	return nil
}

func (r *DigestAuth) fillHeader(req *http.Request) {
	ha2 := getMD5([]string{req.Method, req.URL.String()})
	cnonce := getRandomString(16)
	nc := r.getNonceCount()
	response := getMD5([]string{
		r.ha1,
		r.parts[nonce],
		nc,
		cnonce,
		r.parts[qop],
		ha2,
	})
	header := fmt.Sprintf(
		`Digest username="%s", realm="%s", nonce="%s", uri="%s", qop=%s, nc=%s, cnonce="%s", response="%s"`,
		r.username,
		r.parts[realm],
		r.parts[nonce],
		req.URL.String(),
		r.parts[qop],
		nc,
		cnonce,
		response,
	)

	req.Header.Add(proxyAuthorization, header)
}

type nonceCount int

func (nc nonceCount) String() string {
	c := int(nc)
	return fmt.Sprintf("%08x", c)
}

func getMD5(texts []string) string {
	h := md5.New()
	_, _ = io.WriteString(h, strings.Join(texts, ":"))
	return hex.EncodeToString(h.Sum(nil))
}

func getRandomString(l int) string {
	str := "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	bytes := []byte(str)
	var result []byte
	lstr := len(str) - 1
	for i := 0; i < l; i++ {
		n := getRandomInt(0, lstr)
		result = append(result, bytes[n])
	}
	return string(result)
}

var r = rand.New(rand.NewSource(time.Now().UnixNano()))

func getRandomInt(min, max int) int {
	sub := max - min + 1
	if sub <= 1 {
		return min
	}
	return min + r.Intn(sub)
}
