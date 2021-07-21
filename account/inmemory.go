package account

import (
	"aletheiaware.com/authgo"
	"sync"
	"time"
)

func NewInMemoryManager() authgo.AccountManager {
	return &inMemoryManager{
		emails:    make(map[string]string),
		usernames: make(map[string]string),
		accounts:  make(map[string]*authgo.Account),
		passwords: make(map[string][]byte),
		verified:  make(map[string]bool),
	}
}

type inMemoryManager struct {
	sync.RWMutex
	emails    map[string]string
	usernames map[string]string
	accounts  map[string]*authgo.Account
	passwords map[string][]byte
	verified  map[string]bool
}

func (m *inMemoryManager) New(email, username string, password []byte) (*authgo.Account, error) {
	m.Lock()
	defer m.Unlock()
	if _, ok := m.usernames[email]; ok {
		return nil, authgo.ErrEmailAlreadyRegistered
	}
	if _, ok := m.emails[username]; ok {
		return nil, authgo.ErrUsernameAlreadyRegistered
	}
	h, err := authgo.GeneratePasswordHash(password)
	if err != nil {
		return nil, err
	}
	acc := &authgo.Account{
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

func (m *inMemoryManager) Lookup(username string) (*authgo.Account, error) {
	m.RLock()
	defer m.RUnlock()
	return m.accounts[username], nil
}

func (m *inMemoryManager) Authenticate(username string, password []byte) (*authgo.Account, error) {
	m.RLock()
	defer m.RUnlock()
	acc, ok := m.accounts[username]
	if !ok {
		return nil, authgo.ErrIncorrectCredentials
	}
	hash, ok := m.passwords[username]
	if !ok || !authgo.CheckPasswordHash(hash, password) {
		return nil, authgo.ErrIncorrectCredentials
	}
	return acc, nil
}

func (m *inMemoryManager) Username(email string) (string, error) {
	username, ok := m.usernames[email]
	if !ok {
		return "", authgo.ErrEmailNotRegistered
	}
	return username, nil
}

func (m *inMemoryManager) ChangePassword(username string, password []byte) error {
	h, err := authgo.GeneratePasswordHash(password)
	if err != nil {
		return err
	}
	m.passwords[username] = h
	return nil
}

func (m *inMemoryManager) IsEmailVerified(email string) bool {
	m.RLock()
	defer m.RUnlock()
	return m.verified[email]
}

func (m *inMemoryManager) SetEmailVerified(email string, verified bool) error {
	m.Lock()
	defer m.Unlock()
	m.verified[email] = verified
	return nil
}
