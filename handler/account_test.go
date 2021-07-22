package handler_test

import (
	"aletheiaware.com/authgo/authtest"
	"aletheiaware.com/authgo/authtest/handler"
	"testing"
)

func TestAccount(t *testing.T) {
	handler.Account(t, authtest.NewAuthenticator)
}
