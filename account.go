package authgo

import (
	"errors"
	"sync"
	"time"
)

var (
	ErrIncorrectCredentials      = errors.New("Incorrect Credentials")
	ErrEmailAlreadyRegistered    = errors.New("Email Already Registered")
	ErrUsernameAlreadyRegistered = errors.New("Username Already Registered")
)

type Account struct {
	Email, Username string
	Created         time.Time
}

type AccountManager interface {
	New(string, string, string) (*Account, error)
	Authenticate(Session, string, string) error
	Verified(string) bool
	SetVerified(string, bool) error
}

func NewInMemoryAccountManager() AccountManager {
	return &inMemoryAccountManager{
		emails:    make(map[string]string),
		usernames: make(map[string]string),
		accounts:  make(map[string]*Account),
		passwords: make(map[string]string),
		verified:  make(map[string]bool),
	}
}

type inMemoryAccountManager struct {
	sync.RWMutex
	emails    map[string]string
	usernames map[string]string
	accounts  map[string]*Account
	passwords map[string]string
	verified  map[string]bool
}

func (m *inMemoryAccountManager) New(email, username, password string) (*Account, error) {
	m.Lock()
	defer m.Unlock()
	if _, ok := m.usernames[email]; ok {
		return nil, ErrEmailAlreadyRegistered
	}
	if _, ok := m.emails[username]; ok {
		return nil, ErrUsernameAlreadyRegistered
	}
	h, err := GeneratePasswordHash(password)
	if err != nil {
		return nil, err
	}
	acc := &Account{
		Email:    email,
		Username: username,
		Created:  time.Now(),
	}
	m.emails[username] = email
	m.usernames[email] = username
	m.accounts[username] = acc
	m.passwords[username] = h
	return acc, nil
}

func (m *inMemoryAccountManager) Authenticate(session Session, username, password string) error {
	m.RLock()
	defer m.RUnlock()
	acc, ok := m.accounts[username]
	if !ok {
		return ErrIncorrectCredentials
	}
	pwd, ok := m.passwords[username]
	if !ok || !CheckPasswordHash(pwd, password) {
		return ErrIncorrectCredentials
	}
	session.SetAccount(acc)
	return nil
}

func (m *inMemoryAccountManager) Verified(email string) bool {
	m.RLock()
	defer m.RUnlock()
	return m.verified[email]
}

func (m *inMemoryAccountManager) SetVerified(email string, verified bool) error {
	m.Lock()
	defer m.Unlock()
	m.verified[email] = verified
	return nil
}
