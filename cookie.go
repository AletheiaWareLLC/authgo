package authgo

import (
	"aletheiaware.com/netgo"
	"net/http"
	"time"
)

const (
	COOKIE_SIGN_IN          = "sign-in"
	COOKIE_SIGN_UP          = "sign-up"
	COOKIE_ACCOUNT_PASSWORD = "account-password"
	COOKIE_ACCOUNT_RECOVERY = "account-recovery"
)

func NewCookie(name, value string, timeout time.Duration) *http.Cookie {
	return &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		Expires:  time.Now().Add(timeout),
		Secure:   netgo.IsSecure(),
		HttpOnly: true,
	}
}
