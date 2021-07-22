package handler_test

import (
	"aletheiaware.com/authgo/authtest"
	"aletheiaware.com/authgo/authtest/handler"
	"testing"
)

func TestSignUpSignOutSignInAccount(t *testing.T) {
	handler.SignUpSignOutSignInAccount(t, authtest.NewAuthenticator)
}

func TestAccountPasswordSignOutSignInAccount(t *testing.T) {
	handler.SignUpSignOutSignInAccount(t, authtest.NewAuthenticator)
}

func TestAccountRecoveryAccountPasswordAccount(t *testing.T) {
	handler.SignUpSignOutSignInAccount(t, authtest.NewAuthenticator)
}
