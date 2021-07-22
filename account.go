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
	ErrUsernameNotRegistered     = errors.New("Username Not Registered")
)

type Account struct {
	Email, Username string
	Created         time.Time
}
