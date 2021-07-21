package session

import (
	"aletheiaware.com/authgo"
	"sync"
	"time"
)

func NewInMemoryManager() authgo.SessionManager {
	return &inMemoryManager{
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
		resetTokens:        make(map[string]bool),
		resetCreated:       make(map[string]time.Time),
		resetUsernames:     make(map[string]string),
		resetErrors:        make(map[string]string),
		recoveryTokens:     make(map[string]bool),
		recoveryCreated:    make(map[string]time.Time),
		recoveryEmails:     make(map[string]string),
		recoveryUsernames:  make(map[string]string),
		recoveryChallenges: make(map[string]string),
		recoveryErrors:     make(map[string]string),
	}
}

type inMemoryManager struct {
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
	resetTokens        map[string]bool
	resetCreated       map[string]time.Time
	resetUsernames     map[string]string
	resetErrors        map[string]string
	recoveryTokens     map[string]bool
	recoveryCreated    map[string]time.Time
	recoveryEmails     map[string]string
	recoveryUsernames  map[string]string
	recoveryChallenges map[string]string
	recoveryErrors     map[string]string
}

func (m *inMemoryManager) NewSignUp() (string, error) {
	token, err := authgo.NewSessionToken()
	if err != nil {
		return "", err
	}

	m.signupTokens[token] = true
	m.signupCreated[token] = time.Now()

	return token, nil
}

func (m *inMemoryManager) LookupSignUp(token string) (string, string, string, string, bool) {
	m.RLock()
	defer m.RUnlock()
	ok := m.signupTokens[token]
	created := m.signupCreated[token]
	if !ok || created.Add(authgo.SESSION_SIGN_UP_TIMEOUT).Before(time.Now()) {
		return "", "", "", "", false
	}
	email := m.signupEmails[token]
	username := m.signupUsernames[token]
	challenge := m.signupChallenges[token]
	error := m.signupErrors[token]
	return email, username, challenge, error, ok
}

func (m *inMemoryManager) SetSignUpIdentity(token, email, username string) error {
	m.Lock()
	defer m.Unlock()
	m.signupEmails[token] = email
	m.signupUsernames[token] = username
	return nil
}

func (m *inMemoryManager) SetSignUpChallenge(token, challenge string) error {
	m.Lock()
	defer m.Unlock()
	m.signupChallenges[token] = challenge
	return nil
}

func (m *inMemoryManager) SetSignUpError(token string, errmsg string) {
	m.Lock()
	defer m.Unlock()
	m.signupErrors[token] = errmsg
}

func (m *inMemoryManager) NewSignIn(username string) (string, error) {
	token, err := authgo.NewSessionToken()
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

func (m *inMemoryManager) LookupSignIn(token string) (string, bool, string, bool) {
	m.RLock()
	defer m.RUnlock()
	ok := m.signinTokens[token]
	created := m.signinCreated[token]
	if !ok || created.Add(authgo.SESSION_SIGN_IN_TIMEOUT).Before(time.Now()) {
		return "", false, "", false
	}
	username := m.signinUsernames[token]
	authenticated := m.signinAuths[token]
	error := m.signinErrors[token]
	return username, authenticated, error, ok
}

func (m *inMemoryManager) SetSignInUsername(token string, username string) error {
	m.Lock()
	defer m.Unlock()
	m.signinUsernames[token] = username
	return nil
}

func (m *inMemoryManager) SetSignInAuthenticated(token string, authenticated bool) error {
	m.Lock()
	defer m.Unlock()
	m.signinAuths[token] = authenticated
	return nil
}

func (m *inMemoryManager) SetSignInError(token string, errmsg string) {
	m.Lock()
	defer m.Unlock()
	m.signinErrors[token] = errmsg
}

func (m *inMemoryManager) NewAccountPassword(username string) (string, error) {
	token, err := authgo.NewSessionToken()
	if err != nil {
		return "", err
	}

	m.Lock()
	defer m.Unlock()

	m.resetTokens[token] = true
	m.resetUsernames[token] = username
	m.resetCreated[token] = time.Now()

	return token, nil
}

func (m *inMemoryManager) LookupAccountPassword(token string) (string, string, bool) {
	m.RLock()
	defer m.RUnlock()
	ok := m.resetTokens[token]
	created := m.resetCreated[token]
	if !ok || created.Add(authgo.SESSION_ACCOUNT_PASSWORD_TIMEOUT).Before(time.Now()) {
		return "", "", false
	}
	username := m.resetUsernames[token]
	error := m.resetErrors[token]
	return username, error, ok
}

func (m *inMemoryManager) SetAccountPasswordError(token string, errmsg string) {
	m.Lock()
	defer m.Unlock()
	m.resetErrors[token] = errmsg
}

func (m *inMemoryManager) NewAccountRecovery() (string, error) {
	token, err := authgo.NewSessionToken()
	if err != nil {
		return "", err
	}

	m.Lock()
	defer m.Unlock()

	m.recoveryTokens[token] = true
	m.recoveryCreated[token] = time.Now()

	return token, nil
}

func (m *inMemoryManager) LookupAccountRecovery(token string) (string, string, string, string, bool) {
	m.RLock()
	defer m.RUnlock()
	ok := m.recoveryTokens[token]
	created := m.recoveryCreated[token]
	if !ok || created.Add(authgo.SESSION_ACCOUNT_RECOVERY_TIMEOUT).Before(time.Now()) {
		return "", "", "", "", false
	}
	email := m.recoveryEmails[token]
	username := m.recoveryUsernames[token]
	challenge := m.recoveryChallenges[token]
	error := m.recoveryErrors[token]
	return email, username, challenge, error, ok
}

func (m *inMemoryManager) SetAccountRecoveryEmail(token string, email string) error {
	m.Lock()
	defer m.Unlock()
	m.recoveryEmails[token] = email
	return nil
}

func (m *inMemoryManager) SetAccountRecoveryUsername(token string, username string) error {
	m.Lock()
	defer m.Unlock()
	m.recoveryUsernames[token] = username
	return nil
}

func (m *inMemoryManager) SetAccountRecoveryChallenge(token, challenge string) error {
	m.Lock()
	defer m.Unlock()
	m.recoveryChallenges[token] = challenge
	return nil
}

func (m *inMemoryManager) SetAccountRecoveryError(token string, errmsg string) {
	m.Lock()
	defer m.Unlock()
	m.recoveryErrors[token] = errmsg
}
