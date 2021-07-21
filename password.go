package authgo

import (
	"bytes"
	"errors"
	"golang.org/x/crypto/bcrypt"
)

const (
	MINIMUM_PASSWORD_LENGTH = 12
	MAXIMUM_PASSWORD_LENGTH = 50
)

var (
	ErrPasswordTooShort    = errors.New("Password Too Short")
	ErrPasswordTooLong     = errors.New("Password Too Long")
	ErrPasswordsDoNotMatch = errors.New("Passwords Do Not Match")
)

func ValidatePassword(password []byte) error {
	length := len(password)
	if length < MINIMUM_PASSWORD_LENGTH {
		return ErrPasswordTooShort
	}
	if length > MAXIMUM_PASSWORD_LENGTH {
		return ErrPasswordTooLong
	}
	return nil
}

func MatchPasswords(password, confirmation []byte) error {
	if !bytes.Equal(password, confirmation) {
		return ErrPasswordsDoNotMatch
	}
	return nil
}

func GeneratePasswordHash(password []byte) ([]byte, error) {
	return bcrypt.GenerateFromPassword(password, 14)
}

func CheckPasswordHash(hash, password []byte) bool {
	return bcrypt.CompareHashAndPassword(hash, password) == nil
}
