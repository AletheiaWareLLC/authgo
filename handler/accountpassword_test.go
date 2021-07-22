package handler_test

import (
	"aletheiaware.com/authgo/authtest"
	"aletheiaware.com/authgo/authtest/handler"
	"testing"
)

func TestAccountPassword(t *testing.T) {
	handler.AccountPassword(t, authtest.NewAuthenticator)
}
