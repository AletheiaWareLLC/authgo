package authtest

import (
	"aletheiaware.com/authgo"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

const (
	TEST_EMAIL    = "alice@example.com"
	TEST_USERNAME = "alice"
	TEST_PASSWORD = "password1234"
)

func NewAuthenticator(t *testing.T) authgo.Authenticator {
	t.Helper()
	am := authgo.NewInMemoryAccountManager()
	sm := authgo.NewInMemorySessionManager()
	ev := NewEmailVerifier()
	return authgo.NewAuthenticator(am, sm, ev)
}

func NewTestAccount(t *testing.T, a authgo.Authenticator) *authgo.Account {
	acc, err := a.AccountManager().New(TEST_EMAIL, TEST_USERNAME, TEST_PASSWORD)
	assert.Nil(t, err)
	return acc
}

func SignIn(t *testing.T, a authgo.Authenticator) (string, authgo.Session) {
	t.Helper()
	id, session, err := a.SessionManager().New(authgo.SESSION_SIGN_IN_COOKIE, time.Minute, false)
	assert.Nil(t, err)
	err = a.AccountManager().Authenticate(session, TEST_USERNAME, TEST_PASSWORD)
	assert.Nil(t, err)
	return id, session
}

func SignOut(t *testing.T, a authgo.Authenticator, session string) {
	t.Helper()
	a.SessionManager().Delete(session)
}
