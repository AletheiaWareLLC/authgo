package authgo

import (
	"errors"
	"time"
)

var (
	ErrCredentialsIncorrect      = errors.New("Incorrect Credentials")
	ErrEmailAlreadyRegistered    = errors.New("Email Already Registered")
	ErrUsernameAlreadyRegistered = errors.New("Username Already Registered")
	ErrEmailNotRegistered        = errors.New("Email Not Registered")
	ErrUsernameNotRegistered     = errors.New("Username Not Registered")
	ErrInvalidReferrer           = errors.New("Invalid Referrer")
)

type Account struct {
	ID              int64
	Email, Username string
	Created         time.Time
}
