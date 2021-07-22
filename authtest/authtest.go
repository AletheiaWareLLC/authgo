package authtest

import (
	"aletheiaware.com/authgo"
	"aletheiaware.com/authgo/database"
	"github.com/stretchr/testify/assert"
	"testing"
)

const (
	TEST_EMAIL    = "alice@example.com"
	TEST_USERNAME = "alice"
	TEST_PASSWORD = "password1234"
)

func NewAuthenticator(t *testing.T) authgo.Authenticator {
	t.Helper()
	db := database.NewInMemoryDatabase()
	ev := NewEmailVerifier()
	return authgo.NewAuthenticator(db, ev)
}

func NewTestAccount(t *testing.T, a authgo.Authenticator) *authgo.Account {
	acc, err := a.NewAccount(TEST_EMAIL, TEST_USERNAME, []byte(TEST_PASSWORD))
	assert.Nil(t, err)
	return acc
}

func SignIn(t *testing.T, a authgo.Authenticator) (string, *authgo.Account) {
	t.Helper()
	token, err := a.NewSignInSession(TEST_USERNAME)
	assert.Nil(t, err)
	account, err := a.AuthenticateAccount(TEST_USERNAME, []byte(TEST_PASSWORD))
	assert.Nil(t, err)
	err = a.SetSignInSessionAuthenticated(token, true)
	assert.Nil(t, err)
	return token, account
}

func SignOut(t *testing.T, a authgo.Authenticator, token string) {
	t.Helper()
	a.SetSignInSessionAuthenticated(token, false)
}
