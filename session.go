package authgo

import (
	"aletheiaware.com/cryptogo"
	"net/http"
	"time"
)

const (
	SESSION_SIGN_IN_COOKIE           = "sign-in-session"
	SESSION_SIGN_UP_COOKIE           = "sign-up-session"
	SESSION_ACCOUNT_PASSWORD_COOKIE  = "account-password-session"
	SESSION_ACCOUNT_RECOVERY_COOKIE  = "account-recovery-session"
	SESSION_TOKEN_LENGTH             = 16
	SESSION_SIGN_IN_TIMEOUT          = 30 * time.Minute
	SESSION_SIGN_UP_TIMEOUT          = 10 * time.Minute
	SESSION_ACCOUNT_PASSWORD_TIMEOUT = 5 * time.Minute
	SESSION_ACCOUNT_RECOVERY_TIMEOUT = 5 * time.Minute
)

type SessionManager interface {
	NewSignUp() (string, error)
	LookupSignUp(string) (string, string, string, string, bool)
	SetSignUpIdentity(string, string, string) error
	SetSignUpChallenge(string, string) error
	SetSignUpError(string, string)

	NewSignIn(string) (string, error)
	LookupSignIn(string) (string, bool, string, bool)
	SetSignInUsername(string, string) error
	SetSignInAuthenticated(string, bool) error
	SetSignInError(string, string)

	NewAccountPassword(string) (string, error)
	LookupAccountPassword(string) (string, string, bool)
	SetAccountPasswordError(string, string)

	NewAccountRecovery() (string, error)
	LookupAccountRecovery(string) (string, string, string, string, bool)
	SetAccountRecoveryEmail(string, string) error
	SetAccountRecoveryUsername(string, string) error
	SetAccountRecoveryChallenge(string, string) error
	SetAccountRecoveryError(string, string)
}

func NewSessionToken() (string, error) {
	return cryptogo.RandomString(SESSION_TOKEN_LENGTH)
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

func CurrentSignUp(m SessionManager, r *http.Request) (string, string, string, string, string) {
	c, err := r.Cookie(SESSION_SIGN_UP_COOKIE)
	if err != nil {
		return "", "", "", "", ""
	}
	token := c.Value
	email, username, challenge, errmsg, ok := m.LookupSignUp(token)
	if !ok {
		return "", "", "", "", ""
	}
	return token, email, username, challenge, errmsg
}

func CurrentSignIn(m SessionManager, r *http.Request) (string, string, bool, string) {
	c, err := r.Cookie(SESSION_SIGN_IN_COOKIE)
	if err != nil {
		return "", "", false, ""
	}
	token := c.Value
	username, authenticated, errmsg, ok := m.LookupSignIn(token)
	if !ok {
		return "", "", false, ""
	}
	return token, username, authenticated, errmsg
}

func CurrentAccountPassword(m SessionManager, r *http.Request) (string, string, string) {
	c, err := r.Cookie(SESSION_ACCOUNT_PASSWORD_COOKIE)
	if err != nil {
		return "", "", ""
	}
	token := c.Value
	username, errmsg, ok := m.LookupAccountPassword(token)
	if !ok {
		return "", "", ""
	}
	return token, username, errmsg
}

func CurrentAccountRecovery(m SessionManager, r *http.Request) (string, string, string, string, string) {
	c, err := r.Cookie(SESSION_ACCOUNT_RECOVERY_COOKIE)
	if err != nil {
		return "", "", "", "", ""
	}
	token := c.Value
	email, username, challenge, errmsg, ok := m.LookupAccountRecovery(token)
	if !ok {
		return "", "", "", "", ""
	}
	return token, email, username, challenge, errmsg
}
