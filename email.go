package authgo

import (
	"errors"
	"regexp"
)

const VERIFICATION_CODE_LENGTH = 8

var (
	ErrInvalidEmail               = errors.New("Invalid Email Address")
	ErrIncorrectEmailVerification = errors.New("Incorrect Verification Code")
)

// This is not intended to validate every possible email address, instead a verification code will be sent to ensure the email works
var emails = regexp.MustCompile(`^.+@.+$`)

func ValidateEmail(email string) error {
	if email == "" || !emails.MatchString(email) {
		return ErrInvalidEmail
	}
	return nil
}

type EmailVerifier interface {
	VerifyEmail(email string) (string, error)
}
