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

func NewSignUpSessionCookie(token string) *http.Cookie {
	return NewCookie(COOKIE_SIGN_UP, token, SESSION_SIGN_UP_TIMEOUT)
}

func NewSignInSessionCookie(token string) *http.Cookie {
	return NewCookie(COOKIE_SIGN_IN, token, SESSION_SIGN_IN_TIMEOUT)
}

func NewAccountPasswordSessionCookie(token string) *http.Cookie {
	return NewCookie(COOKIE_ACCOUNT_PASSWORD, token, SESSION_ACCOUNT_PASSWORD_TIMEOUT)
}

func NewAccountRecoverySessionCookie(token string) *http.Cookie {
	return NewCookie(COOKIE_ACCOUNT_RECOVERY, token, SESSION_ACCOUNT_RECOVERY_TIMEOUT)
}
