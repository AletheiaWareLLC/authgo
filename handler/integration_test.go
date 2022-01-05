package handler_test

import (
	"aletheiaware.com/authgo/authtest"
	"aletheiaware.com/authgo/authtest/handler"
	"testing"
)

func TestAccountPasswordSignOutSignInAccount(t *testing.T) {
	handler.SignUpSignOutSignInAccount(t, authtest.NewAuthenticator)
}

func TestAccountRecoveryAccountPasswordAccount(t *testing.T) {
	handler.SignUpSignOutSignInAccount(t, authtest.NewAuthenticator)
}

func TestSignInTokenGetsRefreshed(t *testing.T) {
	handler.SignInTokenGetsRefreshed(t, authtest.NewAuthenticator)
}

func TestSignUpSignOutSignInAccount(t *testing.T) {
	handler.SignUpSignOutSignInAccount(t, authtest.NewAuthenticator)
}

func TestAccountDeactivateSignIn(t *testing.T) {
	handler.AccountDeactivateSignIn(t, authtest.NewAuthenticator)
}

func TestAccountDeactivateSignUp(t *testing.T) {
	handler.AccountDeactivateSignUp(t, authtest.NewAuthenticator)
}
