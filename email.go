package authgo

import (
	"errors"
	"regexp"
)

const (
	MAXIMUM_EMAIL_LENGTH     = 320
	VERIFICATION_CODE_LENGTH = 8
)

var (
	ErrEmailTooLong               = errors.New("Email Too Long")
	ErrEmailInvalid               = errors.New("Invalid Email Address")
	ErrEmailVerificationIncorrect = errors.New("Incorrect Verification Code")
)

// This is not intended to validate every possible email address, instead a verification code will be sent to ensure the email works
var emails = regexp.MustCompile(`^.+@.+$`)

func ValidateEmail(email string) error {
	if len(email) > MAXIMUM_EMAIL_LENGTH {
		return ErrEmailTooLong
	}
	if email == "" || !emails.MatchString(email) {
		return ErrEmailInvalid
	}
	return nil
}

type EmailVerifier interface {
	VerifyEmail(email string) (string, error)
}
