package handler_test

import (
	"aletheiaware.com/authgo"
	"aletheiaware.com/authgo/authtest"
	"aletheiaware.com/authgo/authtest/handler"
	"testing"
)

func TestSignUp(t *testing.T) {
	handler.SignUp(t, func() authgo.Authenticator {
		return authtest.NewAuthenticator(t)
	})
}

func TestSignUpVerification(t *testing.T) {
	handler.SignUpVerification(t, func() authgo.Authenticator {
		return authtest.NewAuthenticator(t)
	})
}
