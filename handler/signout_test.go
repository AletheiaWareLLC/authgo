package handler_test

import (
	"aletheiaware.com/authgo"
	"aletheiaware.com/authgo/authtest"
	"aletheiaware.com/authgo/authtest/handler"
	"testing"
)

func TestSignOut(t *testing.T) {
	handler.SignOut(t, func() authgo.Authenticator {
		return authtest.NewAuthenticator(t)
	})
}
