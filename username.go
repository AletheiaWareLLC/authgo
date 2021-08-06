package authgo

import (
	"errors"
	"unicode"
)

const (
	MINIMUM_USERNAME_LENGTH = 3
	MAXIMUM_USERNAME_LENGTH = 100
)

var (
	ErrUsernameTooShort = errors.New("Username Too Short")
	ErrUsernameTooLong  = errors.New("Username Too Long")
	ErrUsernameInvalid  = errors.New("Username Invalid")
)

func ValidateUsername(username string) error {
	length := len(username)
	if length < MINIMUM_USERNAME_LENGTH {
		return ErrUsernameTooShort
	}
	if length > MAXIMUM_USERNAME_LENGTH {
		return ErrUsernameTooLong
	}
	for _, c := range username {
		if !unicode.IsLetter(c) && !unicode.IsNumber(c) {
			return ErrUsernameInvalid
		}
	}
	return nil
}
