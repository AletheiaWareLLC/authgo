package authgo

import "errors"

const (
	MINIMUM_USERNAME_LENGTH = 3
	MAXIMUM_USERNAME_LENGTH = 100
)

var (
	ErrUsernameTooShort = errors.New("Username Too Short")
	ErrUsernameTooLong  = errors.New("Username Too Long")
)

func ValidateUsername(username string) error {
	length := len(username)
	if length < MINIMUM_USERNAME_LENGTH {
		return ErrUsernameTooShort
	}
	if length > MAXIMUM_USERNAME_LENGTH {
		return ErrUsernameTooLong
	}
	return nil
}
