package handler_test

import (
	"aletheiaware.com/authgo"
	"aletheiaware.com/authgo/authtest"
	"aletheiaware.com/authgo/authtest/handler"
	"testing"
)

func TestAccountRecovery(t *testing.T) {
	handler.AccountRecovery(t, func() authgo.Authenticator {
		return authtest.NewAuthenticator(t)
	})
}

func TestAccountRecoveryVerification(t *testing.T) {
	handler.AccountRecoveryVerification(t, func() authgo.Authenticator {
		return authtest.NewAuthenticator(t)
	})
}
