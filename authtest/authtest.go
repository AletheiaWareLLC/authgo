package authtest

import (
	"aletheiaware.com/authgo"
	"aletheiaware.com/authgo/account"
	"aletheiaware.com/authgo/session"
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
	am := account.NewInMemoryManager()
	sm := session.NewInMemoryManager()
	ev := NewEmailVerifier()
	return authgo.NewAuthenticator(am, sm, ev)
}

func NewTestAccount(t *testing.T, a authgo.Authenticator) *authgo.Account {
	acc, err := a.AccountManager().New(TEST_EMAIL, TEST_USERNAME, []byte(TEST_PASSWORD))
	assert.Nil(t, err)
	return acc
}

func SignIn(t *testing.T, a authgo.Authenticator) (string, *authgo.Account) {
	t.Helper()
	sm := a.SessionManager()
	token, err := sm.NewSignIn(TEST_USERNAME)
	assert.Nil(t, err)
	account, err := a.AccountManager().Authenticate(TEST_USERNAME, []byte(TEST_PASSWORD))
	assert.Nil(t, err)
	return token, account
}

func SignOut(t *testing.T, a authgo.Authenticator, token string) {
	t.Helper()
	a.SessionManager().SetSignInAuthenticated(token, false)
}
