package authgo

import (
	"net/http"
	"time"
)

func NewCookie(name, value string, timeout time.Duration) *http.Cookie {
	return &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		Expires:  time.Now().Add(timeout),
		Secure:   Secure(),
		HttpOnly: true,
	}
}
