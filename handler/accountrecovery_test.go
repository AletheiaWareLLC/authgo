package handler_test

import (
	"aletheiaware.com/authgo/authtest"
	"aletheiaware.com/authgo/authtest/handler"
	"testing"
)

func TestAccountRecovery(t *testing.T) {
	handler.AccountRecovery(t, authtest.NewAuthenticator)
}

func TestAccountRecoveryVerification(t *testing.T) {
	handler.AccountRecoveryVerification(t, authtest.NewAuthenticator)
}
