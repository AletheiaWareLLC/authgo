package authgo

import "errors"

const (
	MINIMUM_USERNAME_LENGTH = 3
	MAXIMUM_USERNAME_LENGTH = 100
)

var ErrInvalidUsername = errors.New("Invalid Username")

func ValidateUsername(username string) error {
	if length := len(username); length < MINIMUM_USERNAME_LENGTH || length > MAXIMUM_USERNAME_LENGTH {
		return ErrInvalidUsername
	}
	return nil
}
