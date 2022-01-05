package handler_test

import (
	"aletheiaware.com/authgo/authtest"
	"aletheiaware.com/authgo/authtest/handler"
	"testing"
)

func TestAccountDeactivate(t *testing.T) {
	handler.AccountDeactivate(t, authtest.NewAuthenticator)
}
