package database

import (
	"aletheiaware.com/authgo"
	"errors"
	"sync"
	"time"
)

var ErrNoSuchRecord = errors.New("No Such Record")

func NewInMemoryDatabase() authgo.Database {
	return &inMemoryDatabase{
		accountEmails:      make(map[string]string),
		accountUsernames:   make(map[string]string),
		accountPasswords:   make(map[string][]byte),
		accountVerified:    make(map[string]bool),
		accountCreated:     make(map[string]time.Time),
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

type inMemoryDatabase struct {
	sync.RWMutex
	accountEmails      map[string]string
	accountUsernames   map[string]string
	accountPasswords   map[string][]byte
	accountVerified    map[string]bool
	accountCreated     map[string]time.Time
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

func (db *inMemoryDatabase) Close() error {
	return nil
}

func (db *inMemoryDatabase) Ping() error {
	return nil
}

func (db *inMemoryDatabase) CreateUser(email, username string, password []byte, created time.Time) (int64, error) {
	db.Lock()
	defer db.Unlock()
	if _, ok := db.accountUsernames[email]; ok {
		return 0, authgo.ErrEmailAlreadyRegistered
	}
	if _, ok := db.accountEmails[username]; ok {
		return 0, authgo.ErrUsernameAlreadyRegistered
	}
	db.accountEmails[username] = email
	db.accountUsernames[email] = username
	db.accountPasswords[username] = password
	db.accountCreated[username] = created
	return 1, nil
}

func (db *inMemoryDatabase) SelectUser(username string) (string, []byte, time.Time, error) {
	email, ok := db.accountEmails[username]
	if !ok {
		return "", nil, time.Time{}, authgo.ErrUsernameNotRegistered
	}
	password := db.accountPasswords[username]
	created := db.accountCreated[username]
	return email, password, created, nil
}

func (db *inMemoryDatabase) LookupUsername(email string) (string, error) {
	username, ok := db.accountUsernames[email]
	if !ok {
		return "", authgo.ErrEmailNotRegistered
	}
	return username, nil
}

func (db *inMemoryDatabase) ChangePassword(username string, password []byte) (int64, error) {
	if _, ok := db.accountEmails[username]; !ok {
		return 0, authgo.ErrUsernameNotRegistered
	}
	db.accountPasswords[username] = password
	return 1, nil
}

func (db *inMemoryDatabase) IsEmailVerified(email string) (bool, error) {
	verified, ok := db.accountVerified[email]
	if !ok {
		return false, authgo.ErrEmailNotRegistered
	}
	return verified, nil
}

func (db *inMemoryDatabase) SetEmailVerified(email string, verified bool) (int64, error) {
	if _, ok := db.accountUsernames[email]; !ok {
		return 0, authgo.ErrEmailNotRegistered
	}
	db.accountVerified[email] = verified
	return 1, nil
}

func (db *inMemoryDatabase) CreateSignUpSession(token string, created time.Time) (int64, error) {
	db.signupTokens[token] = true
	db.signupCreated[token] = created
	return 1, nil
}

func (db *inMemoryDatabase) SelectSignUpSession(token string) (string, string, string, string, time.Time, error) {
	if _, ok := db.signupTokens[token]; !ok {
		return "", "", "", "", time.Time{}, ErrNoSuchRecord
	}
	errmsg := db.signupErrors[token]
	email := db.signupEmails[token]
	username := db.signupUsernames[token]
	challenge := db.signupChallenges[token]
	created := db.signupCreated[token]
	return errmsg, email, username, challenge, created, nil
}

func (db *inMemoryDatabase) UpdateSignUpSessionError(token string, errmsg string) (int64, error) {
	if _, ok := db.signupTokens[token]; !ok {
		return 0, ErrNoSuchRecord
	}
	db.signupErrors[token] = errmsg
	return 1, nil
}

func (db *inMemoryDatabase) UpdateSignUpSessionIdentity(token, email, username string) (int64, error) {
	if _, ok := db.signupTokens[token]; !ok {
		return 0, ErrNoSuchRecord
	}
	db.signupEmails[token] = email
	db.signupUsernames[token] = username
	return 1, nil
}

func (db *inMemoryDatabase) UpdateSignUpSessionChallenge(token, challenge string) (int64, error) {
	if _, ok := db.signupTokens[token]; !ok {
		return 0, ErrNoSuchRecord
	}
	db.signupChallenges[token] = challenge
	return 1, nil
}

func (db *inMemoryDatabase) CreateSignInSession(token string, username string, created time.Time) (int64, error) {
	db.signinTokens[token] = true
	if username != "" {
		db.signinUsernames[token] = username
		db.signinAuths[token] = true
	}
	db.signinCreated[token] = created
	return 1, nil
}

func (db *inMemoryDatabase) SelectSignInSession(token string) (string, string, time.Time, bool, error) {
	if _, ok := db.signinTokens[token]; !ok {
		return "", "", time.Time{}, false, ErrNoSuchRecord
	}
	errmsg := db.signinErrors[token]
	username := db.signinUsernames[token]
	created := db.signinCreated[token]
	authorized := db.signinAuths[token]
	return errmsg, username, created, authorized, nil
}

func (db *inMemoryDatabase) UpdateSignInSessionError(token, errmsg string) (int64, error) {
	if _, ok := db.signinTokens[token]; !ok {
		return 0, ErrNoSuchRecord
	}
	db.signinErrors[token] = errmsg
	return 1, nil
}

func (db *inMemoryDatabase) UpdateSignInSessionUsername(token, username string) (int64, error) {
	if _, ok := db.signinTokens[token]; !ok {
		return 0, ErrNoSuchRecord
	}
	db.signinUsernames[token] = username
	return 1, nil
}

func (db *inMemoryDatabase) UpdateSignInSessionAuthenticated(token string, authorized bool) (int64, error) {
	if _, ok := db.signinTokens[token]; !ok {
		return 0, ErrNoSuchRecord
	}
	db.signinAuths[token] = authorized
	return 1, nil
}

func (db *inMemoryDatabase) CreateAccountPasswordSession(token string, username string, created time.Time) (int64, error) {
	db.resetTokens[token] = true
	db.resetUsernames[token] = username
	db.resetCreated[token] = created
	return 1, nil
}

func (db *inMemoryDatabase) SelectAccountPasswordSession(token string) (string, string, time.Time, error) {
	if _, ok := db.resetTokens[token]; !ok {
		return "", "", time.Time{}, ErrNoSuchRecord
	}
	errmsg := db.resetErrors[token]
	username := db.resetUsernames[token]
	created := db.resetCreated[token]
	return errmsg, username, created, nil
}

func (db *inMemoryDatabase) UpdateAccountPasswordSessionError(token, errmsg string) (int64, error) {
	if _, ok := db.resetTokens[token]; !ok {
		return 0, ErrNoSuchRecord
	}
	db.resetErrors[token] = errmsg
	return 1, nil
}

func (db *inMemoryDatabase) CreateAccountRecoverySession(token string, created time.Time) (int64, error) {
	db.recoveryTokens[token] = true
	db.recoveryCreated[token] = created
	return 1, nil
}

func (db *inMemoryDatabase) SelectAccountRecoverySession(token string) (string, string, string, string, time.Time, error) {
	if _, ok := db.recoveryTokens[token]; !ok {
		return "", "", "", "", time.Time{}, ErrNoSuchRecord
	}
	errmsg := db.recoveryErrors[token]
	email := db.recoveryEmails[token]
	username := db.recoveryUsernames[token]
	challenge := db.recoveryChallenges[token]
	created := db.recoveryCreated[token]
	return errmsg, email, username, challenge, created, nil
}

func (db *inMemoryDatabase) UpdateAccountRecoverySessionError(token, errmsg string) (int64, error) {
	if _, ok := db.recoveryTokens[token]; !ok {
		return 0, ErrNoSuchRecord
	}
	db.recoveryErrors[token] = errmsg
	return 1, nil
}

func (db *inMemoryDatabase) UpdateAccountRecoverySessionEmail(token, email string) (int64, error) {
	if _, ok := db.recoveryTokens[token]; !ok {
		return 0, ErrNoSuchRecord
	}
	db.recoveryEmails[token] = email
	return 1, nil
}

func (db *inMemoryDatabase) UpdateAccountRecoverySessionUsername(token, username string) (int64, error) {
	if _, ok := db.recoveryTokens[token]; !ok {
		return 0, ErrNoSuchRecord
	}
	db.recoveryUsernames[token] = username
	return 1, nil
}

func (db *inMemoryDatabase) UpdateAccountRecoverySessionChallenge(token, challenge string) (int64, error) {
	if _, ok := db.recoveryTokens[token]; !ok {
		return 0, ErrNoSuchRecord
	}
	db.recoveryChallenges[token] = challenge
	return 1, nil
}
