package authgo

import (
	"net/http"
	"time"
)

const (
	SESSION_SIGN_IN_COOKIE          = "sign-in-session"
	SESSION_SIGN_UP_COOKIE          = "sign-up-session"
	SESSION_ACCOUNT_PASSWORD_COOKIE = "account-password-session"
	SESSION_ACCOUNT_RECOVERY_COOKIE = "account-recovery-session"
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

func NewSignUpCookie(token string) *http.Cookie {
	return NewCookie(SESSION_SIGN_UP_COOKIE, token, SESSION_SIGN_UP_TIMEOUT)
}

func NewSignInCookie(token string) *http.Cookie {
	return NewCookie(SESSION_SIGN_IN_COOKIE, token, SESSION_SIGN_IN_TIMEOUT)
}

func NewAccountPasswordCookie(token string) *http.Cookie {
	return NewCookie(SESSION_ACCOUNT_PASSWORD_COOKIE, token, SESSION_ACCOUNT_PASSWORD_TIMEOUT)
}

func NewAccountRecoveryCookie(token string) *http.Cookie {
	return NewCookie(SESSION_ACCOUNT_RECOVERY_COOKIE, token, SESSION_ACCOUNT_RECOVERY_TIMEOUT)
}
