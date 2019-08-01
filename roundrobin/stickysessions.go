package roundrobin

import (
	b64 "encoding/base64"
	"fmt"
	"net/http"
	"net/url"

	"github.com/Gaurav63/security/encryption"
	log "github.com/sirupsen/logrus"
)

// StickySession is a mixin for load balancers that implements layer 7 (http cookie) session affinity
type StickySession struct {
	cookieName string
	options    CookieOptions
	cipherKey  string
}

// CookieOptions has all the options one would like to set on the affinity cookie
type CookieOptions struct {
	HTTPOnly bool
	Secure   bool
	MaxAge   int
}

// NewStickySession creates a new StickySession
func NewStickySession(cookieName string, cipherKey string) *StickySession {
	return &StickySession{cookieName: cookieName, cipherKey: cipherKey}
}

// NewStickySessionWithOptions creates a new StickySession whilst allowing for options to
// shape its affinity cookie such as "httpOnly" or "secure"
func NewStickySessionWithOptions(cookieName string, cipherKey string, options CookieOptions) *StickySession {
	return &StickySession{cookieName: cookieName, cipherKey: cipherKey, options: options}
}

// GetBackend returns the backend URL stored in the sticky cookie, iff the backend is still in the valid list of servers.
func (s *StickySession) GetBackend(req *http.Request, servers []*url.URL, logger *log.Logger) (*url.URL, bool, error) {
	cookie, err := req.Cookie(s.cookieName)
	var plainTextCookie string
	switch err {
	case nil:
	case http.ErrNoCookie:
		return nil, false, nil
	default:
		return nil, false, err
	}

	if len(s.cipherKey) > 0 {
		cipherKeyByte := encryption.Byte32([]byte(s.cipherKey))
		decodedCookieValue, err := b64.StdEncoding.DecodeString(cookie.Value)
		if err != nil {
			logger.Errorf("vulcand/oxy/roundrobin/stickysessions: error when decoding base64: %v.", err)
			return nil, false, err
		}
		plainTextCookieValueBytes, err := encryption.AESDecrypt(decodedCookieValue, cipherKeyByte)

		if err != nil {
			logger.Errorf("vulcand/oxy/roundrobin/stickysessions: error when decrypting cookie: %v.", err)
			return nil, false, err
		}

		plainTextCookie = string(plainTextCookieValueBytes)
	} else {
		plainTextCookie = cookie.Value
	}
	serverURL, err := url.Parse(plainTextCookie)
	if err != nil {
		return nil, false, err
	}

	if s.isBackendAlive(serverURL, servers) {
		fmt.Printf("serverURL:%s\n", serverURL.String())
		return serverURL, true, nil
	}
	return nil, false, nil
}

// StickBackend creates and sets the cookie
func (s *StickySession) StickBackend(backend *url.URL, w *http.ResponseWriter, logger *log.Logger) {
	opt := s.options
	var cookie *http.Cookie

	if len(s.cipherKey) > 0 {
		cipherKeyByte := encryption.Byte32([]byte(s.cipherKey))
		encryptedCookieByte, err := encryption.AESEncrypt([]byte(backend.String()), cipherKeyByte)

		if err != nil {
			logger.Errorf("vulcand/oxy/roundrobin/stickysessions: error when encrypting cookie: %v. Fallback to plaintext cookie", err)
			cookie = &http.Cookie{Name: s.cookieName, Value: backend.String(), Path: "/", HttpOnly: opt.HTTPOnly, Secure: opt.Secure}
			s.cipherKey = ""
		} else {
			cookie = &http.Cookie{Name: s.cookieName, Value: b64.StdEncoding.EncodeToString(encryptedCookieByte), Path: "/", HttpOnly: opt.HTTPOnly, Secure: opt.Secure, MaxAge: opt.MaxAge}
		}
	} else {
		cookie = &http.Cookie{Name: s.cookieName, Value: backend.String(), Path: "/", HttpOnly: opt.HTTPOnly, Secure: opt.Secure, MaxAge: opt.MaxAge}
	}

	http.SetCookie(*w, cookie)
}

func (s *StickySession) isBackendAlive(needle *url.URL, haystack []*url.URL) bool {
	if len(haystack) == 0 {
		return false
	}

	for _, serverURL := range haystack {
		if sameURL(needle, serverURL) {
			return true
		}
	}
	return false
}
