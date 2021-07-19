package authgo

import (
	"errors"
	"golang.org/x/crypto/bcrypt"
)

const MINIMUM_PASSWORD_LENGTH = 12

var (
	ErrPasswordTooShort    = errors.New("Password Too Short")
	ErrPasswordsDoNotMatch = errors.New("Passwords Do Not Match")
)

func ValidatePassword(password string) error {
	if len(password) < MINIMUM_PASSWORD_LENGTH {
		return ErrPasswordTooShort
	}
	return nil
}

func MatchPasswords(password, confirmation string) error {
	if password != confirmation {
		return ErrPasswordsDoNotMatch
	}
	return nil
}

func GeneratePasswordHash(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func CheckPasswordHash(hash, password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}
