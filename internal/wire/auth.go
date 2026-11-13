package wire

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func Signature(token, method, path, stamp, nonce string, body []byte) string {
	b := sha256.Sum256(body)
	h := hmac.New(sha256.New, []byte(token))
	fmt.Fprintf(h, "mnet-agent-v1\n%s\n%s\n%s\n%s\n%x", method, path, stamp, nonce, b)
	return hex.EncodeToString(h.Sum(nil))
}
func ValidSignature(r *http.Request, token string, body []byte, now time.Time) bool {
	stamp, nonce := r.Header.Get("X-Mnet-Time"), r.Header.Get("X-Mnet-Nonce")
	ts, e := strconv.ParseInt(stamp, 10, 64)
	if e != nil || now.Unix()-ts > 30 || ts-now.Unix() > 30 || len(nonce) != 32 {
		return false
	}
	if _, e = hex.DecodeString(nonce); e != nil {
		return false
	}
	expected := Signature(token, r.Method, r.URL.RequestURI(), stamp, nonce, body)
	return hmac.Equal([]byte(expected), []byte(strings.ToLower(r.Header.Get("X-Mnet-Signature"))))
}
