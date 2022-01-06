package authgo_test

import (
	"aletheiaware.com/authgo"
	"aletheiaware.com/authgo/authtest"
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestAuthenticator_CurrentAccount(t *testing.T) {
	t.Run("Valid", func(t *testing.T) {
		auth := authtest.NewAuthenticator(t)
		authtest.NewTestAccount(t, auth)
		token, _ := authtest.SignIn(t, auth)
		request := httptest.NewRequest(http.MethodGet, "/", nil)
		request.AddCookie(auth.NewSignInSessionCookie(token))
		response := httptest.NewRecorder()
		account := auth.CurrentAccount(response, request)
		assert.NotNil(t, account)
		assert.Equal(t, authtest.TEST_EMAIL, account.Email)
		assert.Equal(t, authtest.TEST_USERNAME, account.Username)
	})
	t.Run("Valid_Refresh", func(t *testing.T) {
		auth := authtest.NewAuthenticator(t)
		auth.SetSignInSessionTimeout(time.Second * 6)
		authtest.NewTestAccount(t, auth)
		token, _ := authtest.SignIn(t, auth)
		request := httptest.NewRequest(http.MethodGet, "/", nil)
		request.AddCookie(auth.NewSignInSessionCookie(token))
		response := httptest.NewRecorder()
		time.Sleep(time.Second * 4) // Sleep to ensure expiry is imminent
		account := auth.CurrentAccount(response, request)
		assert.NotNil(t, account)
		assert.Equal(t, authtest.TEST_EMAIL, account.Email)
		assert.Equal(t, authtest.TEST_USERNAME, account.Username)
		// Expect new session
		cookies := response.Result().Cookies()
		assert.Equal(t, 1, len(cookies))
		assert.Equal(t, authgo.COOKIE_SIGN_IN, cookies[0].Name)
		assert.NotEqual(t, token, cookies[0].Value)
	})
	t.Run("NoCookie", func(t *testing.T) {
		auth := authtest.NewAuthenticator(t)
		authtest.NewTestAccount(t, auth)
		request := httptest.NewRequest(http.MethodGet, "/", nil)
		response := httptest.NewRecorder()
		account := auth.CurrentAccount(response, request)
		assert.Nil(t, account)
	})
	t.Run("NoSession", func(t *testing.T) {
		auth := authtest.NewAuthenticator(t)
		authtest.NewTestAccount(t, auth)
		request := httptest.NewRequest(http.MethodGet, "/", nil)
		request.AddCookie(auth.NewSignInSessionCookie("token"))
		response := httptest.NewRecorder()
		account := auth.CurrentAccount(response, request)
		assert.Nil(t, account)
	})
	t.Run("ExpiredSession", func(t *testing.T) {
		auth := authtest.NewAuthenticator(t)
		auth.SetSignInSessionTimeout(time.Nanosecond)
		authtest.NewTestAccount(t, auth)
		token, _ := authtest.SignIn(t, auth)
		request := httptest.NewRequest(http.MethodGet, "/", nil)
		request.AddCookie(auth.NewSignInSessionCookie(token))
		response := httptest.NewRecorder()
		time.Sleep(time.Millisecond) // Sleep to ensure expiry
		account := auth.CurrentAccount(response, request)
		assert.Nil(t, account)
	})
}

func TestAuthenticator_NewAccount(t *testing.T) {
	auth := authtest.NewAuthenticator(t)
	account := authtest.NewTestAccount(t, auth)
	assert.NotNil(t, account)
	assert.Equal(t, authtest.TEST_EMAIL, account.Email)
	assert.Equal(t, authtest.TEST_USERNAME, account.Username)
}

func TestAuthenticator_LookupAccount(t *testing.T) {
	t.Run("DoesNotExist", func(t *testing.T) {
		auth := authtest.NewAuthenticator(t)
		account, err := auth.LookupAccount(authtest.TEST_USERNAME)
		assert.Error(t, authgo.ErrUsernameNotRegistered, err)
		assert.Nil(t, account)
	})
	t.Run("Exists", func(t *testing.T) {
		auth := authtest.NewAuthenticator(t)
		authtest.NewTestAccount(t, auth)
		account, err := auth.LookupAccount(authtest.TEST_USERNAME)
		assert.NoError(t, err)
		assert.NotNil(t, account)
		assert.Equal(t, authtest.TEST_EMAIL, account.Email)
		assert.Equal(t, authtest.TEST_USERNAME, account.Username)
	})
}

func TestAuthenticator_AuthenticateAccount(t *testing.T) {
	t.Run("DoesNotExist", func(t *testing.T) {
		auth := authtest.NewAuthenticator(t)
		account, err := auth.AuthenticateAccount(authtest.TEST_USERNAME, []byte(authtest.TEST_PASSWORD))
		assert.Error(t, authgo.ErrCredentialsIncorrect, err)
		assert.Nil(t, account)
	})
	t.Run("Exists_CredentialsIncorrect", func(t *testing.T) {
		auth := authtest.NewAuthenticator(t)
		authtest.NewTestAccount(t, auth)
		account, err := auth.AuthenticateAccount(authtest.TEST_USERNAME, []byte("1234password"))
		assert.Error(t, authgo.ErrCredentialsIncorrect, err)
		assert.Nil(t, account)
	})
	t.Run("Exists_CredentialsCorrect", func(t *testing.T) {
		auth := authtest.NewAuthenticator(t)
		authtest.NewTestAccount(t, auth)
		account, err := auth.AuthenticateAccount(authtest.TEST_USERNAME, []byte(authtest.TEST_PASSWORD))
		assert.NoError(t, err)
		assert.NotNil(t, account)
		assert.Equal(t, authtest.TEST_EMAIL, account.Email)
		assert.Equal(t, authtest.TEST_USERNAME, account.Username)
	})
}

func TestAuthenticator_LookupUsernameForEmail(t *testing.T) {
	t.Run("DoesNotExist", func(t *testing.T) {
		auth := authtest.NewAuthenticator(t)
		username, err := auth.LookupUsernameForEmail(authtest.TEST_EMAIL)
		assert.Error(t, authgo.ErrUsernameNotRegistered, err)
		assert.Empty(t, username)
	})
	t.Run("Exists", func(t *testing.T) {
		auth := authtest.NewAuthenticator(t)
		authtest.NewTestAccount(t, auth)
		username, err := auth.LookupUsernameForEmail(authtest.TEST_EMAIL)
		assert.NoError(t, err)
		assert.Equal(t, authtest.TEST_USERNAME, username)
	})
}

func TestAuthenticator_ChangePassword(t *testing.T) {
	auth := authtest.NewAuthenticator(t)
	authtest.NewTestAccount(t, auth)
	newPassword := []byte("1234password")
	err := auth.ChangePassword(authtest.TEST_USERNAME, newPassword)
	assert.NoError(t, err)

	// Old password should not work
	account, err := auth.AuthenticateAccount(authtest.TEST_USERNAME, []byte(authtest.TEST_PASSWORD))
	assert.Error(t, authgo.ErrCredentialsIncorrect, err)
	assert.Nil(t, account)

	// New password should work
	account, err = auth.AuthenticateAccount(authtest.TEST_USERNAME, newPassword)
	assert.NotNil(t, account)
	assert.Equal(t, authtest.TEST_EMAIL, account.Email)
	assert.Equal(t, authtest.TEST_USERNAME, account.Username)
}

func TestAuthenticator_DeactivateAccount(t *testing.T) {
	auth := authtest.NewAuthenticator(t)
	account := authtest.NewTestAccount(t, auth)
	err := auth.DeactivateAccount(account)
	assert.NoError(t, err)

	// Should not longer authenticate
	account, err = auth.AuthenticateAccount(authtest.TEST_USERNAME, []byte(authtest.TEST_PASSWORD))
	assert.Error(t, authgo.ErrCredentialsIncorrect, err)
	assert.Nil(t, account)
}

func TestAuthenticator_IsEmailVerified(t *testing.T) {
	auth := authtest.NewAuthenticator(t)

	// Unregistered email is never verified
	assert.False(t, auth.IsEmailVerified(authtest.TEST_EMAIL))

	// New account is not verified
	authtest.NewTestAccount(t, auth)
	assert.False(t, auth.IsEmailVerified(authtest.TEST_EMAIL))
}

func TestAuthenticator_SetEmailVerified(t *testing.T) {
	auth := authtest.NewAuthenticator(t)

	// Cannot verify an unregistered email
	err := auth.SetEmailVerified(authtest.TEST_EMAIL, true)
	assert.Error(t, authgo.ErrEmailNotRegistered)
	err = auth.SetEmailVerified(authtest.TEST_EMAIL, false)
	assert.Error(t, authgo.ErrEmailNotRegistered)

	// Registered account can be verified
	authtest.NewTestAccount(t, auth)
	err = auth.SetEmailVerified(authtest.TEST_EMAIL, true)
	assert.NoError(t, err)
	assert.True(t, auth.IsEmailVerified(authtest.TEST_EMAIL))

	// Registered account can be unverified
	err = auth.SetEmailVerified(authtest.TEST_EMAIL, false)
	assert.NoError(t, err)
	assert.False(t, auth.IsEmailVerified(authtest.TEST_EMAIL))
}

func TestAuthenticator_SignUpSessionTimeout(t *testing.T) {
	auth := authtest.NewAuthenticator(t)
	assert.True(t, auth.SignUpSessionTimeout().Seconds() > 0)
}

func TestAuthenticator_SetSignUpSessionTimeout(t *testing.T) {
	auth := authtest.NewAuthenticator(t)
	auth.SetSignUpSessionTimeout(time.Second * 5)
	assert.True(t, auth.SignUpSessionTimeout().Seconds() == 5)
}

func TestAuthenticator_NewSignUpSessionCookie(t *testing.T) {
	auth := authtest.NewAuthenticator(t)
	token, err := authgo.NewSessionToken()
	assert.NoError(t, err)
	cookie := auth.NewSignUpSessionCookie(token)
	assert.NotNil(t, cookie)
	assert.Equal(t, authgo.COOKIE_SIGN_UP, cookie.Name)
	assert.Equal(t, token, cookie.Value)
}

func TestAuthenticator_CurrentSignUpSession(t *testing.T) {
	t.Run("NoCookie", func(t *testing.T) {
		auth := authtest.NewAuthenticator(t)
		request := httptest.NewRequest(http.MethodGet, "/", nil)
		tok, _, _, _, _, _ := auth.CurrentSignUpSession(request)
		assert.Empty(t, tok)
	})
	t.Run("NoSession", func(t *testing.T) {
		auth := authtest.NewAuthenticator(t)
		request := httptest.NewRequest(http.MethodGet, "/", nil)
		token, err := authgo.NewSessionToken()
		assert.NoError(t, err)
		cookie := auth.NewSignUpSessionCookie(token)
		assert.NotNil(t, cookie)
		request.AddCookie(cookie)
		tok, _, _, _, _, _ := auth.CurrentSignUpSession(request)
		assert.Empty(t, tok)
	})
	t.Run("ExpiredSession", func(t *testing.T) {
		auth := authtest.NewAuthenticator(t)
		auth.SetSignUpSessionTimeout(time.Nanosecond)
		authtest.NewTestAccount(t, auth)
		token, err := auth.NewSignUpSession()
		assert.NoError(t, err)
		cookie := auth.NewSignUpSessionCookie(token)
		assert.NotNil(t, cookie)
		request := httptest.NewRequest(http.MethodGet, "/", nil)
		request.AddCookie(cookie)
		time.Sleep(time.Millisecond) // Sleep to ensure expiry
		tok, _, _, _, _, _ := auth.CurrentSignUpSession(request)
		assert.Empty(t, tok)
	})
	t.Run("Exists", func(t *testing.T) {
		auth := authtest.NewAuthenticator(t)
		authtest.NewTestAccount(t, auth)
		token, err := auth.NewSignUpSession()
		assert.NoError(t, err)
		cookie := auth.NewSignUpSessionCookie(token)
		assert.NotNil(t, cookie)
		request := httptest.NewRequest(http.MethodGet, "/", nil)
		request.AddCookie(cookie)
		tok, _, _, _, _, _ := auth.CurrentSignUpSession(request)
		assert.Equal(t, token, tok)
	})
}

func TestAuthenticator_NewSignUpSession(t *testing.T) {
	auth := authtest.NewAuthenticator(t)
	token, err := auth.NewSignUpSession()
	assert.NoError(t, err)
	email, username, referrer, challenge, errmsg, ok := auth.LookupSignUpSession(token)
	assert.Empty(t, email)
	assert.Empty(t, username)
	assert.Empty(t, referrer)
	assert.Empty(t, challenge)
	assert.Empty(t, errmsg)
	assert.True(t, ok)
}

func TestAuthenticator_LookupSignUpSession(t *testing.T) {
	auth := authtest.NewAuthenticator(t)
	email, username, referrer, challenge, errmsg, ok := auth.LookupSignUpSession("")
	assert.Empty(t, email)
	assert.Empty(t, username)
	assert.Empty(t, referrer)
	assert.Empty(t, challenge)
	assert.Empty(t, errmsg)
	assert.False(t, ok)
}

func TestAuthenticator_SetSignUpSessionError(t *testing.T) {
	auth := authtest.NewAuthenticator(t)
	token, err := auth.NewSignUpSession()
	assert.NoError(t, err)
	error := "ERR"
	auth.SetSignUpSessionError(token, error)
	email, username, referrer, challenge, errmsg, ok := auth.LookupSignUpSession(token)
	assert.Empty(t, email)
	assert.Empty(t, username)
	assert.Empty(t, referrer)
	assert.Empty(t, challenge)
	assert.Equal(t, error, errmsg)
	assert.True(t, ok)
}

func TestAuthenticator_SetSignUpSessionIdentity(t *testing.T) {
	auth := authtest.NewAuthenticator(t)
	token, err := auth.NewSignUpSession()
	assert.NoError(t, err)
	auth.SetSignUpSessionIdentity(token, authtest.TEST_EMAIL, authtest.TEST_USERNAME)
	email, username, referrer, challenge, errmsg, ok := auth.LookupSignUpSession(token)
	assert.Equal(t, authtest.TEST_EMAIL, email)
	assert.Equal(t, authtest.TEST_USERNAME, username)
	assert.Empty(t, referrer)
	assert.Empty(t, challenge)
	assert.Empty(t, errmsg)
	assert.True(t, ok)
}

func TestAuthenticator_SetSignUpSessionReferrer(t *testing.T) {
	auth := authtest.NewAuthenticator(t)
	token, err := auth.NewSignUpSession()
	assert.NoError(t, err)
	referrer := "foobar"
	auth.SetSignUpSessionReferrer(token, referrer)
	email, username, ref, challenge, errmsg, ok := auth.LookupSignUpSession(token)
	assert.Empty(t, email)
	assert.Empty(t, username)
	assert.Equal(t, referrer, ref)
	assert.Empty(t, challenge)
	assert.Empty(t, errmsg)
	assert.True(t, ok)
}

func TestAuthenticator_SetSignUpSessionChallenge(t *testing.T) {
	auth := authtest.NewAuthenticator(t)
	token, err := auth.NewSignUpSession()
	assert.NoError(t, err)
	challenge := "abcd1234"
	auth.SetSignUpSessionChallenge(token, challenge)
	email, username, referrer, chal, errmsg, ok := auth.LookupSignUpSession(token)
	assert.Empty(t, email)
	assert.Empty(t, username)
	assert.Empty(t, referrer)
	assert.Equal(t, challenge, chal)
	assert.Empty(t, errmsg)
	assert.True(t, ok)
}

func TestAuthenticator_SignInSessionTimeout(t *testing.T) {
	auth := authtest.NewAuthenticator(t)
	assert.True(t, auth.SignInSessionTimeout().Seconds() > 0)
}

func TestAuthenticator_SetSignInSessionTimeout(t *testing.T) {
	auth := authtest.NewAuthenticator(t)
	auth.SetSignInSessionTimeout(time.Second * 5)
	assert.True(t, auth.SignInSessionTimeout().Seconds() == 5)
}

func TestAuthenticator_NewSignInSessionCookie(t *testing.T) {
	auth := authtest.NewAuthenticator(t)
	token, err := authgo.NewSessionToken()
	assert.NoError(t, err)
	cookie := auth.NewSignInSessionCookie(token)
	assert.NotNil(t, cookie)
	assert.Equal(t, authgo.COOKIE_SIGN_IN, cookie.Name)
	assert.Equal(t, token, cookie.Value)
}

func TestAuthenticator_CurrentSignInSession(t *testing.T) {
	t.Run("NoCookie", func(t *testing.T) {
		auth := authtest.NewAuthenticator(t)
		request := httptest.NewRequest(http.MethodGet, "/", nil)
		tok, username, authenticated, _, _ := auth.CurrentSignInSession(request)
		assert.Empty(t, tok)
		assert.Empty(t, username)
		assert.False(t, authenticated)
	})
	t.Run("NoSession", func(t *testing.T) {
		auth := authtest.NewAuthenticator(t)
		request := httptest.NewRequest(http.MethodGet, "/", nil)
		token, err := authgo.NewSessionToken()
		assert.NoError(t, err)
		cookie := auth.NewSignInSessionCookie(token)
		assert.NotNil(t, cookie)
		request.AddCookie(cookie)
		tok, username, authenticated, _, _ := auth.CurrentSignInSession(request)
		assert.Empty(t, tok)
		assert.Empty(t, username)
		assert.False(t, authenticated)
	})
	t.Run("ExpiredSession", func(t *testing.T) {
		auth := authtest.NewAuthenticator(t)
		auth.SetSignInSessionTimeout(time.Nanosecond)
		authtest.NewTestAccount(t, auth)
		token, _ := authtest.SignIn(t, auth)
		request := httptest.NewRequest(http.MethodGet, "/", nil)
		request.AddCookie(auth.NewSignInSessionCookie(token))
		time.Sleep(time.Millisecond) // Sleep to ensure expiry
		tok, username, authenticated, _, _ := auth.CurrentSignInSession(request)
		assert.Empty(t, tok)
		assert.Empty(t, username)
		assert.False(t, authenticated)
	})
	t.Run("Exists", func(t *testing.T) {
		auth := authtest.NewAuthenticator(t)
		authtest.NewTestAccount(t, auth)
		token, _ := authtest.SignIn(t, auth)
		request := httptest.NewRequest(http.MethodGet, "/", nil)
		request.AddCookie(auth.NewSignInSessionCookie(token))
		tok, username, authenticated, _, _ := auth.CurrentSignInSession(request)
		assert.Equal(t, token, tok)
		assert.Equal(t, username, authtest.TEST_USERNAME)
		assert.True(t, authenticated)
	})
}

func TestAuthenticator_NewSignInSession(t *testing.T) {
	auth := authtest.NewAuthenticator(t)
	token, err := auth.NewSignInSession("", false)
	assert.NoError(t, err)
	username, authenticated, _, errmsg, ok := auth.LookupSignInSession(token)
	assert.Empty(t, username)
	assert.False(t, authenticated)
	assert.Empty(t, errmsg)
	assert.True(t, ok)
}

func TestAuthenticator_LookupSignInSession(t *testing.T) {
	auth := authtest.NewAuthenticator(t)
	username, authenticated, _, errmsg, ok := auth.LookupSignInSession("")
	assert.Empty(t, username)
	assert.False(t, authenticated)
	assert.Empty(t, errmsg)
	assert.False(t, ok)
}

func TestAuthenticator_SetSignInSessionError(t *testing.T) {
	auth := authtest.NewAuthenticator(t)
	token, err := auth.NewSignInSession("", false)
	assert.NoError(t, err)
	error := "ERR"
	auth.SetSignInSessionError(token, error)
	username, authenticated, _, errmsg, ok := auth.LookupSignInSession(token)
	assert.Empty(t, username)
	assert.False(t, authenticated)
	assert.Equal(t, error, errmsg)
	assert.True(t, ok)
}

func TestAuthenticator_SetSignInSessionUsername(t *testing.T) {
	auth := authtest.NewAuthenticator(t)
	token, err := auth.NewSignInSession("", false)
	assert.NoError(t, err)
	auth.SetSignInSessionUsername(token, authtest.TEST_USERNAME)
	username, authenticated, _, errmsg, ok := auth.LookupSignInSession(token)
	assert.Equal(t, authtest.TEST_USERNAME, username)
	assert.False(t, authenticated)
	assert.Empty(t, errmsg)
	assert.True(t, ok)
}

func TestAuthenticator_SetSignInSessionAuthenticated(t *testing.T) {
	auth := authtest.NewAuthenticator(t)
	token, err := auth.NewSignInSession("", false)
	assert.NoError(t, err)
	auth.SetSignInSessionAuthenticated(token, true)
	username, authenticated, _, errmsg, ok := auth.LookupSignInSession(token)
	assert.Empty(t, username)
	assert.True(t, authenticated)
	assert.Empty(t, errmsg)
	assert.True(t, ok)
}

func TestAuthenticator_AccountPasswordSessionTimeout(t *testing.T) {
	auth := authtest.NewAuthenticator(t)
	assert.True(t, auth.AccountPasswordSessionTimeout().Seconds() > 0)
}

func TestAuthenticator_SetAccountPasswordSessionTimeout(t *testing.T) {
	auth := authtest.NewAuthenticator(t)
	auth.SetAccountPasswordSessionTimeout(time.Second * 5)
	assert.True(t, auth.AccountPasswordSessionTimeout().Seconds() == 5)
}

func TestAuthenticator_NewAccountPasswordSessionCookie(t *testing.T) {
	auth := authtest.NewAuthenticator(t)
	token, err := authgo.NewSessionToken()
	assert.NoError(t, err)
	cookie := auth.NewAccountPasswordSessionCookie(token)
	assert.NotNil(t, cookie)
	assert.Equal(t, authgo.COOKIE_ACCOUNT_PASSWORD, cookie.Name)
	assert.Equal(t, token, cookie.Value)
}

func TestAuthenticator_CurrentAccountPasswordSession(t *testing.T) {
	t.Run("NoCookie", func(t *testing.T) {
		auth := authtest.NewAuthenticator(t)
		request := httptest.NewRequest(http.MethodGet, "/", nil)
		tok, username, _ := auth.CurrentAccountPasswordSession(request)
		assert.Empty(t, tok)
		assert.Empty(t, username)
	})
	t.Run("NoSession", func(t *testing.T) {
		auth := authtest.NewAuthenticator(t)
		request := httptest.NewRequest(http.MethodGet, "/", nil)
		token, err := authgo.NewSessionToken()
		assert.NoError(t, err)
		cookie := auth.NewAccountPasswordSessionCookie(token)
		assert.NotNil(t, cookie)
		request.AddCookie(cookie)
		tok, username, _ := auth.CurrentAccountPasswordSession(request)
		assert.Empty(t, tok)
		assert.Empty(t, username)
	})
	t.Run("ExpiredSession", func(t *testing.T) {
		auth := authtest.NewAuthenticator(t)
		auth.SetAccountPasswordSessionTimeout(time.Nanosecond)
		token, err := auth.NewAccountPasswordSession(authtest.TEST_USERNAME)
		assert.NoError(t, err)
		request := httptest.NewRequest(http.MethodGet, "/", nil)
		request.AddCookie(auth.NewAccountPasswordSessionCookie(token))
		time.Sleep(time.Millisecond) // Sleep to ensure expiry
		tok, username, _ := auth.CurrentAccountPasswordSession(request)
		assert.Empty(t, tok)
		assert.Empty(t, username)
	})
	t.Run("Exists", func(t *testing.T) {
		auth := authtest.NewAuthenticator(t)
		token, err := auth.NewAccountPasswordSession(authtest.TEST_USERNAME)
		assert.NoError(t, err)
		request := httptest.NewRequest(http.MethodGet, "/", nil)
		request.AddCookie(auth.NewAccountPasswordSessionCookie(token))
		tok, username, _ := auth.CurrentAccountPasswordSession(request)
		assert.Equal(t, token, tok)
		assert.Equal(t, authtest.TEST_USERNAME, username)
	})
}

func TestAuthenticator_NewAccountPasswordSession(t *testing.T) {
	auth := authtest.NewAuthenticator(t)
	token, err := auth.NewAccountPasswordSession("")
	assert.NoError(t, err)
	username, errmsg, ok := auth.LookupAccountPasswordSession(token)
	assert.Empty(t, username)
	assert.Empty(t, errmsg)
	assert.True(t, ok)
}

func TestAuthenticator_LookupAccountPasswordSession(t *testing.T) {
	auth := authtest.NewAuthenticator(t)
	username, errmsg, ok := auth.LookupAccountPasswordSession("")
	assert.Empty(t, username)
	assert.Empty(t, errmsg)
	assert.False(t, ok)
}

func TestAuthenticator_SetAccountPasswordSessionError(t *testing.T) {
	auth := authtest.NewAuthenticator(t)
	token, err := auth.NewAccountPasswordSession("")
	assert.NoError(t, err)
	error := "ERR"
	auth.SetAccountPasswordSessionError(token, error)
	username, errmsg, ok := auth.LookupAccountPasswordSession(token)
	assert.Empty(t, username)
	assert.Equal(t, error, errmsg)
	assert.True(t, ok)
}

func TestAuthenticator_AccountRecoverySessionTimeout(t *testing.T) {
	auth := authtest.NewAuthenticator(t)
	assert.True(t, auth.AccountRecoverySessionTimeout().Seconds() > 0)
}

func TestAuthenticator_SetAccountRecoverySessionTimeout(t *testing.T) {
	auth := authtest.NewAuthenticator(t)
	auth.SetAccountRecoverySessionTimeout(time.Second * 5)
	assert.True(t, auth.AccountRecoverySessionTimeout().Seconds() == 5)
}

func TestAuthenticator_NewAccountRecoverySessionCookie(t *testing.T) {
	auth := authtest.NewAuthenticator(t)
	token, err := authgo.NewSessionToken()
	assert.NoError(t, err)
	cookie := auth.NewAccountRecoverySessionCookie(token)
	assert.NotNil(t, cookie)
	assert.Equal(t, authgo.COOKIE_ACCOUNT_RECOVERY, cookie.Name)
	assert.Equal(t, token, cookie.Value)
}

func TestAuthenticator_CurrentAccountRecoverySession(t *testing.T) {
	t.Run("NoCookie", func(t *testing.T) {
		auth := authtest.NewAuthenticator(t)
		request := httptest.NewRequest(http.MethodGet, "/", nil)
		tok, _, _, _, _ := auth.CurrentAccountRecoverySession(request)
		assert.Empty(t, tok)
	})
	t.Run("NoSession", func(t *testing.T) {
		auth := authtest.NewAuthenticator(t)
		request := httptest.NewRequest(http.MethodGet, "/", nil)
		token, err := authgo.NewSessionToken()
		assert.NoError(t, err)
		cookie := auth.NewAccountRecoverySessionCookie(token)
		assert.NotNil(t, cookie)
		request.AddCookie(cookie)
		tok, _, _, _, _ := auth.CurrentAccountRecoverySession(request)
		assert.Empty(t, tok)
	})
	t.Run("ExpiredSession", func(t *testing.T) {
		auth := authtest.NewAuthenticator(t)
		auth.SetAccountRecoverySessionTimeout(time.Nanosecond)
		token, err := auth.NewAccountRecoverySession()
		assert.NoError(t, err)
		request := httptest.NewRequest(http.MethodGet, "/", nil)
		request.AddCookie(auth.NewAccountRecoverySessionCookie(token))
		time.Sleep(time.Millisecond) // Sleep to ensure expiry
		tok, _, _, _, _ := auth.CurrentAccountRecoverySession(request)
		assert.Empty(t, tok)
	})
	t.Run("Exists", func(t *testing.T) {
		auth := authtest.NewAuthenticator(t)
		token, err := auth.NewAccountRecoverySession()
		assert.NoError(t, err)
		request := httptest.NewRequest(http.MethodGet, "/", nil)
		request.AddCookie(auth.NewAccountRecoverySessionCookie(token))
		tok, _, _, _, _ := auth.CurrentAccountRecoverySession(request)
		assert.Equal(t, token, tok)
	})
}

func TestAuthenticator_NewAccountRecoverySession(t *testing.T) {
	auth := authtest.NewAuthenticator(t)
	token, err := auth.NewAccountRecoverySession()
	assert.NoError(t, err)
	email, username, challenge, errmsg, ok := auth.LookupAccountRecoverySession(token)
	assert.Empty(t, email)
	assert.Empty(t, username)
	assert.Empty(t, challenge)
	assert.Empty(t, errmsg)
	assert.True(t, ok)
}

func TestAuthenticator_LookupAccountRecoverySession(t *testing.T) {
	auth := authtest.NewAuthenticator(t)
	email, username, challenge, errmsg, ok := auth.LookupAccountRecoverySession("")
	assert.Empty(t, email)
	assert.Empty(t, username)
	assert.Empty(t, challenge)
	assert.Empty(t, errmsg)
	assert.False(t, ok)
}

func TestAuthenticator_SetAccountRecoverySessionError(t *testing.T) {
	auth := authtest.NewAuthenticator(t)
	token, err := auth.NewAccountRecoverySession()
	assert.NoError(t, err)
	error := "ERR"
	auth.SetAccountRecoverySessionError(token, error)
	email, username, challenge, errmsg, ok := auth.LookupAccountRecoverySession(token)
	assert.Empty(t, email)
	assert.Empty(t, username)
	assert.Empty(t, challenge)
	assert.Equal(t, error, errmsg)
	assert.True(t, ok)
}

func TestAuthenticator_SetAccountRecoverySessionEmail(t *testing.T) {
	auth := authtest.NewAuthenticator(t)
	token, err := auth.NewAccountRecoverySession()
	assert.NoError(t, err)
	auth.SetAccountRecoverySessionEmail(token, authtest.TEST_EMAIL)
	email, username, challenge, errmsg, ok := auth.LookupAccountRecoverySession(token)
	assert.Equal(t, authtest.TEST_EMAIL, email)
	assert.Empty(t, username)
	assert.Empty(t, challenge)
	assert.Empty(t, errmsg)
	assert.True(t, ok)
}

func TestAuthenticator_SetAccountRecoverySessionUsername(t *testing.T) {
	auth := authtest.NewAuthenticator(t)
	token, err := auth.NewAccountRecoverySession()
	assert.NoError(t, err)
	auth.SetAccountRecoverySessionUsername(token, authtest.TEST_USERNAME)
	email, username, challenge, errmsg, ok := auth.LookupAccountRecoverySession(token)
	assert.Empty(t, email)
	assert.Equal(t, authtest.TEST_USERNAME, username)
	assert.Empty(t, challenge)
	assert.Empty(t, errmsg)
	assert.True(t, ok)
}

func TestAuthenticator_SetAccountRecoverySessionChallenge(t *testing.T) {
	auth := authtest.NewAuthenticator(t)
	token, err := auth.NewAccountRecoverySession()
	assert.NoError(t, err)
	challenge := "ERR"
	auth.SetAccountRecoverySessionChallenge(token, challenge)
	email, username, chal, errmsg, ok := auth.LookupAccountRecoverySession(token)
	assert.Empty(t, email)
	assert.Empty(t, username)
	assert.Equal(t, challenge, chal)
	assert.Empty(t, errmsg)
	assert.True(t, ok)
}
