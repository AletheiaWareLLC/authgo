package handler_test

import (
	"aletheiaware.com/authgo/authtest"
	"aletheiaware.com/authgo/authtest/handler"
	"testing"
)

func TestSignIn(t *testing.T) {
	handler.SignIn(t, authtest.NewAuthenticator)
}
