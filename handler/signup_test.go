package handler_test

import (
	"aletheiaware.com/authgo/authtest"
	"aletheiaware.com/authgo/authtest/handler"
	"testing"
)

func TestSignUp(t *testing.T) {
	handler.SignUp(t, authtest.NewAuthenticator)
}

func TestSignUpVerification(t *testing.T) {
	handler.SignUpVerification(t, authtest.NewAuthenticator)
}
