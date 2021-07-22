package handler_test

import (
	"aletheiaware.com/authgo/authtest"
	"aletheiaware.com/authgo/authtest/handler"
	"testing"
)

func TestSignOut(t *testing.T) {
	handler.SignOut(t, authtest.NewAuthenticator)
}
