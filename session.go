package authgo

import (
	"aletheiaware.com/cryptogo"
	"net/http"
	"sync"
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

	NewAccountPassword() (string, error)
	LookupAccountPassword(string) (string, bool)
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

func CurrentAccountPassword(m SessionManager, r *http.Request) (string, string) {
	c, err := r.Cookie(SESSION_ACCOUNT_PASSWORD_COOKIE)
	if err != nil {
		return "", ""
	}
	token := c.Value
	errmsg, ok := m.LookupAccountPassword(token)
	if !ok {
		return "", ""
	}
	return token, errmsg
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

func NewInMemorySessionManager() SessionManager {
	return &inMemorySessionManager{
		signupTokens:       make(map[string]bool),
		signupCreated:      make(map[string]time.Time),
		signupEmails:       make(map[string]string),
		signupUsernames:    make(map[string]string),
		signupChallenges:   make(map[string]string),
		signupErrors:       make(map[string]string),
		signinTokens:       make(map[string]bool),
		signinCreated:      make(map[string]time.Time),
		signinUsernames:    make(map[string]string),
		signinAuths:        make(map[string]bool),
		signinErrors:       make(map[string]string),
		passwordTokens:     make(map[string]bool),
		passwordCreated:    make(map[string]time.Time),
		passwordErrors:     make(map[string]string),
		recoveryTokens:     make(map[string]bool),
		recoveryCreated:    make(map[string]time.Time),
		recoveryEmails:     make(map[string]string),
		recoveryUsernames:  make(map[string]string),
		recoveryChallenges: make(map[string]string),
		recoveryErrors:     make(map[string]string),
	}
}

type inMemorySessionManager struct {
	sync.RWMutex
	signupTokens       map[string]bool
	signupCreated      map[string]time.Time
	signupEmails       map[string]string
	signupUsernames    map[string]string
	signupChallenges   map[string]string
	signupErrors       map[string]string
	signinTokens       map[string]bool
	signinCreated      map[string]time.Time
	signinUsernames    map[string]string
	signinAuths        map[string]bool
	signinErrors       map[string]string
	passwordTokens     map[string]bool
	passwordCreated    map[string]time.Time
	passwordErrors     map[string]string
	recoveryTokens     map[string]bool
	recoveryCreated    map[string]time.Time
	recoveryEmails     map[string]string
	recoveryUsernames  map[string]string
	recoveryChallenges map[string]string
	recoveryErrors     map[string]string
}

func (m *inMemorySessionManager) NewSignUp() (string, error) {
	token, err := NewSessionToken()
	if err != nil {
		return "", err
	}

	m.signupTokens[token] = true
	m.signupCreated[token] = time.Now()

	return token, nil
}

func (m *inMemorySessionManager) LookupSignUp(token string) (string, string, string, string, bool) {
	m.RLock()
	defer m.RUnlock()
	ok := m.signupTokens[token]
	created := m.signupCreated[token]
	if !ok || created.Add(SESSION_SIGN_UP_TIMEOUT).Before(time.Now()) {
		return "", "", "", "", false
	}
	email := m.signupEmails[token]
	username := m.signupUsernames[token]
	challenge := m.signupChallenges[token]
	error := m.signupErrors[token]
	return email, username, challenge, error, ok
}

func (m *inMemorySessionManager) SetSignUpIdentity(token, email, username string) error {
	m.Lock()
	defer m.Unlock()
	m.signupEmails[token] = email
	m.signupUsernames[token] = username
	return nil
}

func (m *inMemorySessionManager) SetSignUpChallenge(token, challenge string) error {
	m.Lock()
	defer m.Unlock()
	m.signupChallenges[token] = challenge
	return nil
}

func (m *inMemorySessionManager) SetSignUpError(token string, errmsg string) {
	m.Lock()
	defer m.Unlock()
	m.signupErrors[token] = errmsg
}

func (m *inMemorySessionManager) NewSignIn(username string) (string, error) {
	token, err := NewSessionToken()
	if err != nil {
		return "", err
	}

	m.Lock()
	defer m.Unlock()

	m.signinTokens[token] = true
	m.signinCreated[token] = time.Now()

	if username != "" {
		m.signinUsernames[token] = username
		m.signinAuths[token] = true
	}

	return token, nil
}

func (m *inMemorySessionManager) LookupSignIn(token string) (string, bool, string, bool) {
	m.RLock()
	defer m.RUnlock()
	ok := m.signinTokens[token]
	created := m.signinCreated[token]
	if !ok || created.Add(SESSION_SIGN_IN_TIMEOUT).Before(time.Now()) {
		return "", false, "", false
	}
	username := m.signinUsernames[token]
	authenticated := m.signinAuths[token]
	error := m.signinErrors[token]
	return username, authenticated, error, ok
}

func (m *inMemorySessionManager) SetSignInUsername(token string, username string) error {
	m.Lock()
	defer m.Unlock()
	m.signinUsernames[token] = username
	return nil
}

func (m *inMemorySessionManager) SetSignInAuthenticated(token string, authenticated bool) error {
	m.Lock()
	defer m.Unlock()
	m.signinAuths[token] = authenticated
	return nil
}

func (m *inMemorySessionManager) SetSignInError(token string, errmsg string) {
	m.Lock()
	defer m.Unlock()
	m.signinErrors[token] = errmsg
}

func (m *inMemorySessionManager) NewAccountPassword() (string, error) {
	token, err := NewSessionToken()
	if err != nil {
		return "", err
	}

	m.Lock()
	defer m.Unlock()

	m.passwordTokens[token] = true
	m.passwordCreated[token] = time.Now()

	return token, nil
}

func (m *inMemorySessionManager) LookupAccountPassword(token string) (string, bool) {
	m.RLock()
	defer m.RUnlock()
	ok := m.passwordTokens[token]
	created := m.passwordCreated[token]
	if !ok || created.Add(SESSION_ACCOUNT_PASSWORD_TIMEOUT).Before(time.Now()) {
		return "", false
	}
	error := m.passwordErrors[token]
	return error, ok
}

func (m *inMemorySessionManager) SetAccountPasswordError(token string, errmsg string) {
	m.Lock()
	defer m.Unlock()
	m.passwordErrors[token] = errmsg
}

func (m *inMemorySessionManager) NewAccountRecovery() (string, error) {
	token, err := NewSessionToken()
	if err != nil {
		return "", err
	}

	m.Lock()
	defer m.Unlock()

	m.recoveryTokens[token] = true
	m.recoveryCreated[token] = time.Now()

	return token, nil
}

func (m *inMemorySessionManager) LookupAccountRecovery(token string) (string, string, string, string, bool) {
	m.RLock()
	defer m.RUnlock()
	ok := m.recoveryTokens[token]
	created := m.recoveryCreated[token]
	if !ok || created.Add(SESSION_ACCOUNT_RECOVERY_TIMEOUT).Before(time.Now()) {
		return "", "", "", "", false
	}
	email := m.recoveryEmails[token]
	username := m.recoveryUsernames[token]
	challenge := m.recoveryChallenges[token]
	error := m.recoveryErrors[token]
	return email, username, challenge, error, ok
}

func (m *inMemorySessionManager) SetAccountRecoveryEmail(token string, email string) error {
	m.Lock()
	defer m.Unlock()
	m.recoveryEmails[token] = email
	return nil
}

func (m *inMemorySessionManager) SetAccountRecoveryUsername(token string, username string) error {
	m.Lock()
	defer m.Unlock()
	m.recoveryUsernames[token] = username
	return nil
}

func (m *inMemorySessionManager) SetAccountRecoveryChallenge(token, challenge string) error {
	m.Lock()
	defer m.Unlock()
	m.recoveryChallenges[token] = challenge
	return nil
}

func (m *inMemorySessionManager) SetAccountRecoveryError(token string, errmsg string) {
	m.Lock()
	defer m.Unlock()
	m.recoveryErrors[token] = errmsg
}
