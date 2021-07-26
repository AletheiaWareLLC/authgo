package database

import (
	"aletheiaware.com/authgo"
	"errors"
	"sync"
	"time"
)

var (
	ErrNoSuchRecord = errors.New("No Such Record")
	nextId          = int64(1)
)

func NextId() int64 {
	n := nextId
	nextId = nextId + 1
	return n
}

func NewInMemoryDatabase() *InMemoryDatabase {
	return &InMemoryDatabase{
		AccountId:         make(map[string]int64),
		AccountEmail:      make(map[string]string),
		AccountUsername:   make(map[string]string),
		AccountPassword:   make(map[string][]byte),
		AccountVerified:    make(map[string]bool),
		AccountCreated:     make(map[string]time.Time),
		SignupToken:       make(map[string]bool),
		SignupCreated:      make(map[string]time.Time),
		SignupEmail:       make(map[string]string),
		SignupUsername:    make(map[string]string),
		SignupChallenge:   make(map[string]string),
		SignupError:       make(map[string]string),
		SigninToken:       make(map[string]bool),
		SigninCreated:      make(map[string]time.Time),
		SigninUsername:    make(map[string]string),
		SigninAuth:        make(map[string]bool),
		SigninError:       make(map[string]string),
		ResetToken:        make(map[string]bool),
		ResetCreated:       make(map[string]time.Time),
		ResetUsername:     make(map[string]string),
		ResetError:        make(map[string]string),
		RecoveryToken:     make(map[string]bool),
		RecoveryCreated:    make(map[string]time.Time),
		RecoveryEmail:     make(map[string]string),
		RecoveryUsername:  make(map[string]string),
		RecoveryChallenge: make(map[string]string),
		RecoveryError:     make(map[string]string),
	}
}

type InMemoryDatabase struct {
	sync.RWMutex
	AccountId         map[string]int64
	AccountEmail      map[string]string
	AccountUsername   map[string]string
	AccountPassword   map[string][]byte
	AccountVerified    map[string]bool
	AccountCreated     map[string]time.Time
	SignupToken       map[string]bool
	SignupCreated      map[string]time.Time
	SignupEmail       map[string]string
	SignupUsername    map[string]string
	SignupChallenge   map[string]string
	SignupError       map[string]string
	SigninToken       map[string]bool
	SigninCreated      map[string]time.Time
	SigninUsername    map[string]string
	SigninAuth        map[string]bool
	SigninError       map[string]string
	ResetToken        map[string]bool
	ResetCreated       map[string]time.Time
	ResetUsername     map[string]string
	ResetError        map[string]string
	RecoveryToken     map[string]bool
	RecoveryCreated    map[string]time.Time
	RecoveryEmail     map[string]string
	RecoveryUsername  map[string]string
	RecoveryChallenge map[string]string
	RecoveryError     map[string]string
}

func (db *InMemoryDatabase) Close() error {
	return nil
}

func (db *InMemoryDatabase) Ping() error {
	return nil
}

func (db *InMemoryDatabase) CreateUser(email, username string, password []byte, created time.Time) (int64, error) {
	db.Lock()
	defer db.Unlock()
	if _, ok := db.AccountUsername[email]; ok {
		return 0, authgo.ErrEmailAlreadyRegistered
	}
	if _, ok := db.AccountEmail[username]; ok {
		return 0, authgo.ErrUsernameAlreadyRegistered
	}
	id := NextId()
	db.AccountId[username] = id
	db.AccountEmail[username] = email
	db.AccountUsername[email] = username
	db.AccountPassword[username] = password
	db.AccountCreated[username] = created
	return id, nil
}

func (db *InMemoryDatabase) SelectUser(username string) (int64, string, []byte, time.Time, error) {
	id, ok := db.AccountId[username]
	if !ok {
		return 0, "", nil, time.Time{}, authgo.ErrUsernameNotRegistered
	}
	email := db.AccountEmail[username]
	password := db.AccountPassword[username]
	created := db.AccountCreated[username]
	return id, email, password, created, nil
}

func (db *InMemoryDatabase) LookupUsername(email string) (string, error) {
	username, ok := db.AccountUsername[email]
	if !ok {
		return "", authgo.ErrEmailNotRegistered
	}
	return username, nil
}

func (db *InMemoryDatabase) ChangePassword(username string, password []byte) (int64, error) {
	if _, ok := db.AccountEmail[username]; !ok {
		return 0, authgo.ErrUsernameNotRegistered
	}
	db.AccountPassword[username] = password
	return 1, nil
}

func (db *InMemoryDatabase) IsEmailVerified(email string) (bool, error) {
	verified, ok := db.AccountVerified[email]
	if !ok {
		return false, authgo.ErrEmailNotRegistered
	}
	return verified, nil
}

func (db *InMemoryDatabase) SetEmailVerified(email string, verified bool) (int64, error) {
	if _, ok := db.AccountUsername[email]; !ok {
		return 0, authgo.ErrEmailNotRegistered
	}
	db.AccountVerified[email] = verified
	return 1, nil
}

func (db *InMemoryDatabase) CreateSignUpSession(token string, created time.Time) (int64, error) {
	db.SignupToken[token] = true
	db.SignupCreated[token] = created
	return 1, nil
}

func (db *InMemoryDatabase) SelectSignUpSession(token string) (string, string, string, string, time.Time, error) {
	if _, ok := db.SignupToken[token]; !ok {
		return "", "", "", "", time.Time{}, ErrNoSuchRecord
	}
	errmsg := db.SignupError[token]
	email := db.SignupEmail[token]
	username := db.SignupUsername[token]
	challenge := db.SignupChallenge[token]
	created := db.SignupCreated[token]
	return errmsg, email, username, challenge, created, nil
}

func (db *InMemoryDatabase) UpdateSignUpSessionError(token string, errmsg string) (int64, error) {
	if _, ok := db.SignupToken[token]; !ok {
		return 0, ErrNoSuchRecord
	}
	db.SignupError[token] = errmsg
	return 1, nil
}

func (db *InMemoryDatabase) UpdateSignUpSessionIdentity(token, email, username string) (int64, error) {
	if _, ok := db.SignupToken[token]; !ok {
		return 0, ErrNoSuchRecord
	}
	db.SignupEmail[token] = email
	db.SignupUsername[token] = username
	return 1, nil
}

func (db *InMemoryDatabase) UpdateSignUpSessionChallenge(token, challenge string) (int64, error) {
	if _, ok := db.SignupToken[token]; !ok {
		return 0, ErrNoSuchRecord
	}
	db.SignupChallenge[token] = challenge
	return 1, nil
}

func (db *InMemoryDatabase) CreateSignInSession(token string, username string, created time.Time) (int64, error) {
	db.SigninToken[token] = true
	if username != "" {
		db.SigninUsername[token] = username
		db.SigninAuth[token] = true
	}
	db.SigninCreated[token] = created
	return 1, nil
}

func (db *InMemoryDatabase) SelectSignInSession(token string) (string, string, time.Time, bool, error) {
	if _, ok := db.SigninToken[token]; !ok {
		return "", "", time.Time{}, false, ErrNoSuchRecord
	}
	errmsg := db.SigninError[token]
	username := db.SigninUsername[token]
	created := db.SigninCreated[token]
	authorized := db.SigninAuth[token]
	return errmsg, username, created, authorized, nil
}

func (db *InMemoryDatabase) UpdateSignInSessionError(token, errmsg string) (int64, error) {
	if _, ok := db.SigninToken[token]; !ok {
		return 0, ErrNoSuchRecord
	}
	db.SigninError[token] = errmsg
	return 1, nil
}

func (db *InMemoryDatabase) UpdateSignInSessionUsername(token, username string) (int64, error) {
	if _, ok := db.SigninToken[token]; !ok {
		return 0, ErrNoSuchRecord
	}
	db.SigninUsername[token] = username
	return 1, nil
}

func (db *InMemoryDatabase) UpdateSignInSessionAuthenticated(token string, authorized bool) (int64, error) {
	if _, ok := db.SigninToken[token]; !ok {
		return 0, ErrNoSuchRecord
	}
	db.SigninAuth[token] = authorized
	return 1, nil
}

func (db *InMemoryDatabase) CreateAccountPasswordSession(token string, username string, created time.Time) (int64, error) {
	db.ResetToken[token] = true
	db.ResetUsername[token] = username
	db.ResetCreated[token] = created
	return 1, nil
}

func (db *InMemoryDatabase) SelectAccountPasswordSession(token string) (string, string, time.Time, error) {
	if _, ok := db.ResetToken[token]; !ok {
		return "", "", time.Time{}, ErrNoSuchRecord
	}
	errmsg := db.ResetError[token]
	username := db.ResetUsername[token]
	created := db.ResetCreated[token]
	return errmsg, username, created, nil
}

func (db *InMemoryDatabase) UpdateAccountPasswordSessionError(token, errmsg string) (int64, error) {
	if _, ok := db.ResetToken[token]; !ok {
		return 0, ErrNoSuchRecord
	}
	db.ResetError[token] = errmsg
	return 1, nil
}

func (db *InMemoryDatabase) CreateAccountRecoverySession(token string, created time.Time) (int64, error) {
	db.RecoveryToken[token] = true
	db.RecoveryCreated[token] = created
	return 1, nil
}

func (db *InMemoryDatabase) SelectAccountRecoverySession(token string) (string, string, string, string, time.Time, error) {
	if _, ok := db.RecoveryToken[token]; !ok {
		return "", "", "", "", time.Time{}, ErrNoSuchRecord
	}
	errmsg := db.RecoveryError[token]
	email := db.RecoveryEmail[token]
	username := db.RecoveryUsername[token]
	challenge := db.RecoveryChallenge[token]
	created := db.RecoveryCreated[token]
	return errmsg, email, username, challenge, created, nil
}

func (db *InMemoryDatabase) UpdateAccountRecoverySessionError(token, errmsg string) (int64, error) {
	if _, ok := db.RecoveryToken[token]; !ok {
		return 0, ErrNoSuchRecord
	}
	db.RecoveryError[token] = errmsg
	return 1, nil
}

func (db *InMemoryDatabase) UpdateAccountRecoverySessionEmail(token, email string) (int64, error) {
	if _, ok := db.RecoveryToken[token]; !ok {
		return 0, ErrNoSuchRecord
	}
	db.RecoveryEmail[token] = email
	return 1, nil
}

func (db *InMemoryDatabase) UpdateAccountRecoverySessionUsername(token, username string) (int64, error) {
	if _, ok := db.RecoveryToken[token]; !ok {
		return 0, ErrNoSuchRecord
	}
	db.RecoveryUsername[token] = username
	return 1, nil
}

func (db *InMemoryDatabase) UpdateAccountRecoverySessionChallenge(token, challenge string) (int64, error) {
	if _, ok := db.RecoveryToken[token]; !ok {
		return 0, ErrNoSuchRecord
	}
	db.RecoveryChallenge[token] = challenge
	return 1, nil
}
