package authgo

import (
	"errors"
	"time"
)

var (
	ErrIncorrectCredentials      = errors.New("Incorrect Credentials")
	ErrEmailAlreadyRegistered    = errors.New("Email Already Registered")
	ErrUsernameAlreadyRegistered = errors.New("Username Already Registered")
	ErrEmailNotRegistered        = errors.New("Email Not Registered")
)

type Account struct {
	Email, Username string
	Created         time.Time
}

type AccountManager interface {
	New(string, string, []byte) (*Account, error)
	Lookup(string) (*Account, error)
	Authenticate(string, []byte) (*Account, error)
	Username(string) (string, error)
	ChangePassword(string, []byte) error
	IsEmailVerified(string) bool
	SetEmailVerified(string, bool) error
}
