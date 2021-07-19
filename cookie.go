package authgo

import (
	"net/http"
	"time"
)

func NewCookie(name, value string, timeout time.Duration, secure bool) *http.Cookie {
	return &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		Expires:  time.Now().Add(timeout),
		Secure:   secure,
		HttpOnly: true,
	}
}

func Cookies(name string, r *http.Request) (cookies []*http.Cookie) {
	for _, c := range r.Cookies() {
		if c.Name == name {
			cookies = append(cookies, c)
		}
	}
	return
}
