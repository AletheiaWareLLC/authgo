package handler

import (
	"aletheiaware.com/authgo"
	"aletheiaware.com/authgo/authtest"
	"aletheiaware.com/authgo/handler"
	"github.com/stretchr/testify/assert"
	"html/template"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"testing/fstest"
	"time"
)

func AccountPasswordSignOutSignInAccount(t *testing.T, a func(*testing.T) authgo.Authenticator) {
	fs := fstest.MapFS{
		"account.go.html": {
			Data: []byte(`{{.Account.Username}}`),
		},
		"account-password.go.html": {
			Data: []byte(`{{.Error}}`),
		},
		"sign-out.go.html": {
			Data: []byte(`{{.Error}}`),
		},
		"sign-in.go.html": {
			Data: []byte(`{{.Error}}`),
		},
	}
	tmpl, err := template.ParseFS(fs, "*.go.html")
	assert.Nil(t, err)

	auth := a(t)
	authtest.NewTestAccount(t, auth)
	assert.Nil(t, auth.SetEmailVerified(authtest.TEST_EMAIL, true))
	mux := http.NewServeMux()
	handler.AttachAuthenticationHandlers(mux, auth, tmpl)
	token, _ := authtest.SignIn(t, auth)
	signInCookie := auth.NewSignInSessionCookie(token)
	newPassword := "foobarfoobar"

	// Account Password
	values := url.Values{}
	values.Add("password", newPassword)
	values.Add("confirmation", newPassword)
	reader := strings.NewReader(values.Encode())
	request := httptest.NewRequest(http.MethodPost, "/account-password", reader)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(signInCookie)
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	result := response.Result()
	assert.Equal(t, http.StatusFound, result.StatusCode)
	cookies := result.Cookies()
	assert.Equal(t, 2, len(cookies))
	assert.Equal(t, authgo.COOKIE_SIGN_IN, cookies[0].Name)
	assert.Equal(t, authgo.COOKIE_ACCOUNT_PASSWORD, cookies[1].Name)
	u, err := result.Location()
	assert.Nil(t, err)
	assert.Equal(t, "/account", u.String())

	// Sign Out
	request = httptest.NewRequest(http.MethodPost, "/sign-out", nil)
	request.AddCookie(signInCookie)
	response = httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	result = response.Result()
	assert.Equal(t, http.StatusFound, result.StatusCode)
	u, err = result.Location()
	assert.Nil(t, err)
	assert.Equal(t, "/", u.String())

	// Sign In
	reader = strings.NewReader("username=" + authtest.TEST_USERNAME + "&password=" + newPassword)
	request = httptest.NewRequest(http.MethodPost, "/sign-in", reader)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response = httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	result = response.Result()
	assert.Equal(t, http.StatusFound, result.StatusCode)
	cookies = result.Cookies()
	assert.Equal(t, 1, len(cookies))
	assert.Equal(t, authgo.COOKIE_SIGN_IN, cookies[0].Name)
	body, err := io.ReadAll(result.Body)
	assert.Nil(t, err)
	assert.Empty(t, string(body))
	u, err = result.Location()
	assert.Nil(t, err)
	assert.Equal(t, "/account", u.String())

	// Account
	request = httptest.NewRequest(http.MethodGet, "/account", nil)
	request.AddCookie(signInCookie)
	response = httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	result = response.Result()
	assert.Equal(t, http.StatusOK, result.StatusCode)
	body, err = io.ReadAll(result.Body)
	assert.Nil(t, err)
	assert.Equal(t, authtest.TEST_USERNAME, string(body))
}

func AccountRecoveryAccountPasswordAccount(t *testing.T, a func(*testing.T) authgo.Authenticator) {
	fs := fstest.MapFS{
		"account.go.html": {
			Data: []byte(`{{.Account.Username}}`),
		},
		"account-password.go.html": {
			Data: []byte(`{{.Error}}`),
		},
		"account-recovery.go.html": {
			Data: []byte(`{{.Error}}{{.Email}}`),
		},
		"account-recovery-verification.go.html": {
			Data: []byte(`{{.Error}}{{.Username}}`),
		},
	}
	tmpl, err := template.ParseFS(fs, "*.go.html")
	assert.Nil(t, err)

	auth := a(t)
	authtest.NewTestAccount(t, auth)
	mux := http.NewServeMux()
	handler.AttachAuthenticationHandlers(mux, auth, tmpl)
	newPassword := "foobarfoobar"

	// Account Recovery
	values := url.Values{}
	values.Add("email", authtest.TEST_EMAIL)
	reader := strings.NewReader(values.Encode())
	request := httptest.NewRequest(http.MethodPost, "/account-recovery", reader)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	result := response.Result()
	assert.Equal(t, http.StatusFound, result.StatusCode)
	cookies := result.Cookies()
	assert.Equal(t, 1, len(cookies))
	assert.Equal(t, authgo.COOKIE_ACCOUNT_RECOVERY, cookies[0].Name)
	u, err := result.Location()
	assert.Nil(t, err)
	assert.Equal(t, "/account-recovery-verification", u.String())

	// Account Recovery Verification
	values = url.Values{}
	values.Add("verification", authtest.TEST_CHALLENGE)
	reader = strings.NewReader(values.Encode())
	request = httptest.NewRequest(http.MethodPost, "/account-recovery-verification", reader)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(cookies[0])
	response = httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	result = response.Result()
	assert.Equal(t, http.StatusFound, result.StatusCode)
	cookies = result.Cookies()
	assert.Equal(t, 1, len(cookies))
	assert.Equal(t, authgo.COOKIE_SIGN_IN, cookies[0].Name)
	u, err = result.Location()
	assert.Nil(t, err)
	assert.Equal(t, "/account-password", u.String())

	// Account Password
	values = url.Values{}
	values.Add("password", newPassword)
	values.Add("confirmation", newPassword)
	reader = strings.NewReader(values.Encode())
	request = httptest.NewRequest(http.MethodPost, "/account-password", reader)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(cookies[0])
	response = httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	result = response.Result()
	assert.Equal(t, http.StatusFound, result.StatusCode)
	cookies = result.Cookies()
	assert.Equal(t, 2, len(cookies))
	assert.Equal(t, authgo.COOKIE_SIGN_IN, cookies[0].Name)
	assert.Equal(t, authgo.COOKIE_ACCOUNT_PASSWORD, cookies[1].Name)
	u, err = result.Location()
	assert.Nil(t, err)
	assert.Equal(t, "/account", u.String())

	// Account
	request = httptest.NewRequest(http.MethodGet, "/account", nil)
	request.AddCookie(cookies[0])
	response = httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	result = response.Result()
	assert.Equal(t, http.StatusOK, result.StatusCode)
	body, err := io.ReadAll(result.Body)
	assert.Nil(t, err)
	assert.Equal(t, authtest.TEST_USERNAME, string(body))
}

func SignInTokenGetsRefreshed(t *testing.T, a func(*testing.T) authgo.Authenticator) {
	fs := fstest.MapFS{
		"account.go.html": {
			Data: []byte(`{{.Account.Username}}`),
		},
	}
	tmpl, err := template.ParseFS(fs, "*.go.html")
	assert.Nil(t, err)

	auth := a(t)
	auth.SetSignInSessionTimeout(15 * time.Second)
	authtest.NewTestAccount(t, auth)
	assert.Nil(t, auth.SetEmailVerified(authtest.TEST_EMAIL, true))
	mux := http.NewServeMux()
	handler.AttachAuthenticationHandlers(mux, auth, tmpl)
	token, _ := authtest.SignIn(t, auth)
	signInCookie := auth.NewSignInSessionCookie(token)

	// Sleep for 5s, the get /account - sign in session should not be refreshed
	time.Sleep(5 * time.Second)
	request := httptest.NewRequest(http.MethodGet, "/account", nil)
	request.AddCookie(signInCookie)
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	result := response.Result()
	assert.Equal(t, http.StatusOK, result.StatusCode)
	cookies := result.Cookies()
	assert.Equal(t, 0, len(cookies))
	body, err := io.ReadAll(result.Body)
	assert.Nil(t, err)
	assert.Equal(t, authtest.TEST_USERNAME, string(body))

	// Sleep for another 5s, the get /account - sign in session should be refreshed
	time.Sleep(5 * time.Second)
	request = httptest.NewRequest(http.MethodGet, "/account", nil)
	request.AddCookie(signInCookie)
	response = httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	result = response.Result()
	assert.Equal(t, http.StatusOK, result.StatusCode)
	cookies = result.Cookies()
	assert.Equal(t, 1, len(cookies))
	assert.Equal(t, authgo.COOKIE_SIGN_IN, cookies[0].Name)
	body, err = io.ReadAll(result.Body)
	assert.Nil(t, err)
	assert.Equal(t, authtest.TEST_USERNAME, string(body))
}

func SignUpSignOutSignInAccount(t *testing.T, a func(*testing.T) authgo.Authenticator) {
	fs := fstest.MapFS{
		"sign-up.go.html": {
			Data: []byte(`{{.Error}}{{.Email}}{{.Username}}`),
		},
		"sign-up-verification.go.html": {
			Data: []byte(`{{.Error}}`),
		},
		"sign-out.go.html": {
			Data: []byte(`{{.Error}}`),
		},
		"sign-in.go.html": {
			Data: []byte(`{{.Error}}`),
		},
		"account.go.html": {
			Data: []byte(`{{.Account.Username}}`),
		},
	}
	tmpl, err := template.ParseFS(fs, "*.go.html")
	assert.Nil(t, err)

	auth := a(t)
	mux := http.NewServeMux()
	handler.AttachAuthenticationHandlers(mux, auth, tmpl)

	// Sign Up
	values := url.Values{}
	values.Add("email", authtest.TEST_EMAIL)
	values.Add("username", authtest.TEST_USERNAME)
	values.Add("password", authtest.TEST_PASSWORD)
	values.Add("confirmation", authtest.TEST_PASSWORD)
	reader := strings.NewReader(values.Encode())
	request := httptest.NewRequest(http.MethodPost, "/sign-up", reader)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	result := response.Result()
	assert.Equal(t, http.StatusFound, result.StatusCode)
	cookies := result.Cookies()
	assert.Equal(t, 1, len(cookies))
	assert.Equal(t, authgo.COOKIE_SIGN_UP, cookies[0].Name)
	u, err := result.Location()
	assert.Nil(t, err)
	assert.Equal(t, "/sign-up-verification", u.String())

	// Sign Up Verification
	values = url.Values{}
	values.Add("verification", authtest.TEST_CHALLENGE)
	reader = strings.NewReader(values.Encode())
	request = httptest.NewRequest(http.MethodPost, "/sign-up-verification", reader)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(cookies[0])
	response = httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	result = response.Result()
	assert.Equal(t, http.StatusFound, result.StatusCode)
	cookies = result.Cookies()
	assert.Equal(t, 1, len(cookies))
	assert.Equal(t, authgo.COOKIE_SIGN_IN, cookies[0].Name)
	u, err = result.Location()
	assert.Nil(t, err)
	assert.Equal(t, "/account", u.String())

	// Sign Out
	request = httptest.NewRequest(http.MethodPost, "/sign-out", nil)
	request.AddCookie(cookies[0])
	response = httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	result = response.Result()
	assert.Equal(t, http.StatusFound, result.StatusCode)
	u, err = result.Location()
	assert.Nil(t, err)
	assert.Equal(t, "/", u.String())

	// Sign In
	reader = strings.NewReader("username=" + authtest.TEST_USERNAME + "&password=" + authtest.TEST_PASSWORD)
	request = httptest.NewRequest(http.MethodPost, "/sign-in", reader)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response = httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	result = response.Result()
	assert.Equal(t, http.StatusFound, result.StatusCode)
	cookies = result.Cookies()
	assert.Equal(t, 1, len(cookies))
	assert.Equal(t, authgo.COOKIE_SIGN_IN, cookies[0].Name)
	body, err := io.ReadAll(result.Body)
	assert.Nil(t, err)
	assert.Empty(t, string(body))
	u, err = result.Location()
	assert.Nil(t, err)
	assert.Equal(t, "/account", u.String())

	// Account
	request = httptest.NewRequest(http.MethodGet, "/account", nil)
	request.AddCookie(cookies[0])
	response = httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	result = response.Result()
	assert.Equal(t, http.StatusOK, result.StatusCode)
	body, err = io.ReadAll(result.Body)
	assert.Nil(t, err)
	assert.Equal(t, authtest.TEST_USERNAME, string(body))
}
