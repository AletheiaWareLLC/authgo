package authtest

import "aletheiaware.com/authgo"

const TEST_CHALLENGE = "abcd1234"

func NewEmailVerifier() authgo.EmailVerifier {
	return &emailVerifier{}
}

type emailVerifier struct{}

func (v *emailVerifier) VerifyEmail(email string) (string, error) {
	return TEST_CHALLENGE, authgo.ValidateEmail(email)
}
