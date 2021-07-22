package handler_test

import (
	"aletheiaware.com/authgo"
	"aletheiaware.com/authgo/authtest"
	"aletheiaware.com/authgo/authtest/handler"
	"testing"
)

func TestSignUpSignOutSignInAccount(t *testing.T) {
	handler.SignUpSignOutSignInAccount(t, func() authgo.Authenticator {
		return authtest.NewAuthenticator(t)
	})
}

func TestAccountPasswordSignOutSignInAccount(t *testing.T) {
	handler.SignUpSignOutSignInAccount(t, func() authgo.Authenticator {
		return authtest.NewAuthenticator(t)
	})
}

func TestAccountRecoveryAccountPasswordAccount(t *testing.T) {
	handler.SignUpSignOutSignInAccount(t, func() authgo.Authenticator {
		return authtest.NewAuthenticator(t)
	})
}
