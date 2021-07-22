package handler_test

import (
	"aletheiaware.com/authgo"
	"aletheiaware.com/authgo/authtest"
	"aletheiaware.com/authgo/authtest/handler"
	"testing"
)

func TestSignIn(t *testing.T) {
	handler.SignIn(t, func() authgo.Authenticator {
		return authtest.NewAuthenticator(t)
	})
}
