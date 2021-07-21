package handler_test

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
)

func TestSignUpSignOutSignInAccount(t *testing.T) {
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

	a := authtest.NewAuthenticator(t)
	mux := http.NewServeMux()
	handler.AttachHandlers(a, mux, tmpl)

	// Sign Up
	request := httptest.NewRequest(http.MethodGet, "/sign-up", nil)
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	result := response.Result()
	assert.Equal(t, http.StatusOK, result.StatusCode)
	body, err := io.ReadAll(result.Body)
	assert.Nil(t, err)
	assert.Empty(t, string(body))
	cookies := result.Cookies()
	assert.Equal(t, 1, len(cookies))
	assert.Equal(t, authgo.SESSION_SIGN_UP_COOKIE, cookies[0].Name)
	values := url.Values{}
	values.Add("email", authtest.TEST_EMAIL)
	values.Add("username", authtest.TEST_USERNAME)
	values.Add("password", authtest.TEST_PASSWORD)
	values.Add("confirmation", authtest.TEST_PASSWORD)
	reader := strings.NewReader(values.Encode())
	request = httptest.NewRequest(http.MethodPost, "/sign-up", reader)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(cookies[0])
	response = httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	result = response.Result()
	assert.Equal(t, http.StatusFound, result.StatusCode)
	u, err := result.Location()
	assert.Nil(t, err)
	assert.Equal(t, "/sign-up-verification", u.String())

	// Sign Up Verification
	request = httptest.NewRequest(http.MethodGet, "/sign-up-verification", nil)
	request.AddCookie(cookies[0])
	response = httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	result = response.Result()
	assert.Equal(t, http.StatusOK, result.StatusCode)
	body, err = io.ReadAll(result.Body)
	assert.Nil(t, err)
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
	assert.Equal(t, authgo.SESSION_SIGN_IN_COOKIE, cookies[0].Name)
	u, err = result.Location()
	assert.Nil(t, err)
	assert.Equal(t, "/", u.String())

	// Sign Out
	request = httptest.NewRequest(http.MethodGet, "/sign-out", nil)
	request.AddCookie(cookies[0])
	response = httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	result = response.Result()
	assert.Equal(t, http.StatusOK, result.StatusCode)
	body, err = io.ReadAll(result.Body)
	assert.Nil(t, err)
	assert.Empty(t, string(body))
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
	request = httptest.NewRequest(http.MethodGet, "/sign-in", nil)
	response = httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	result = response.Result()
	assert.Equal(t, http.StatusOK, result.StatusCode)
	body, err = io.ReadAll(result.Body)
	assert.Nil(t, err)
	assert.Empty(t, string(body))
	cookies = result.Cookies()
	assert.Equal(t, 1, len(cookies))
	assert.Equal(t, authgo.SESSION_SIGN_IN_COOKIE, cookies[0].Name)
	reader = strings.NewReader("username=" + authtest.TEST_USERNAME + "&password=" + authtest.TEST_PASSWORD)
	request = httptest.NewRequest(http.MethodPost, "/sign-in", reader)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(cookies[0])
	response = httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	result = response.Result()
	assert.Equal(t, http.StatusFound, result.StatusCode)
	body, err = io.ReadAll(result.Body)
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

func TestAccountPasswordSignOutSignInAccount(t *testing.T) {
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

	a := authtest.NewAuthenticator(t)
	authtest.NewTestAccount(t, a)
	assert.Nil(t, a.AccountManager().SetEmailVerified(authtest.TEST_EMAIL, true))
	mux := http.NewServeMux()
	handler.AttachHandlers(a, mux, tmpl)
	token, _ := authtest.SignIn(t, a)
	newPassword := "foobarfoobar"

	// Account Password
	request := httptest.NewRequest(http.MethodGet, "/account-password", nil)
	request.AddCookie(authgo.NewSignInCookie(token))
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	result := response.Result()
	assert.Equal(t, http.StatusOK, result.StatusCode)
	body, err := io.ReadAll(result.Body)
	assert.Nil(t, err)
	assert.Empty(t, string(body))
	cookies := result.Cookies()
	assert.Equal(t, 2, len(cookies))
	assert.Equal(t, authgo.SESSION_SIGN_IN_COOKIE, cookies[0].Name)
	assert.Equal(t, authgo.SESSION_ACCOUNT_PASSWORD_COOKIE, cookies[1].Name)
	values := url.Values{}
	values.Add("password", newPassword)
	values.Add("confirmation", newPassword)
	reader := strings.NewReader(values.Encode())
	request = httptest.NewRequest(http.MethodPost, "/account-password", reader)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(cookies[0])
	request.AddCookie(cookies[1])
	response = httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	result = response.Result()
	assert.Equal(t, http.StatusFound, result.StatusCode)
	cookies = result.Cookies()
	assert.Equal(t, 1, len(cookies))
	assert.Equal(t, authgo.SESSION_SIGN_IN_COOKIE, cookies[0].Name)
	u, err := result.Location()
	assert.Nil(t, err)
	assert.Equal(t, "/account", u.String())

	// Sign Out
	request = httptest.NewRequest(http.MethodGet, "/sign-out", nil)
	request.AddCookie(cookies[0])
	response = httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	result = response.Result()
	assert.Equal(t, http.StatusOK, result.StatusCode)
	body, err = io.ReadAll(result.Body)
	assert.Nil(t, err)
	assert.Empty(t, string(body))
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
	request = httptest.NewRequest(http.MethodGet, "/sign-in", nil)
	response = httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	result = response.Result()
	assert.Equal(t, http.StatusOK, result.StatusCode)
	body, err = io.ReadAll(result.Body)
	assert.Nil(t, err)
	assert.Empty(t, string(body))
	cookies = result.Cookies()
	assert.Equal(t, 1, len(cookies))
	assert.Equal(t, authgo.SESSION_SIGN_IN_COOKIE, cookies[0].Name)
	reader = strings.NewReader("username=" + authtest.TEST_USERNAME + "&password=" + newPassword)
	request = httptest.NewRequest(http.MethodPost, "/sign-in", reader)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(cookies[0])
	response = httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	result = response.Result()
	assert.Equal(t, http.StatusFound, result.StatusCode)
	body, err = io.ReadAll(result.Body)
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

func TestAccountRecoveryAccountPasswordAccount(t *testing.T) {
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

	a := authtest.NewAuthenticator(t)
	authtest.NewTestAccount(t, a)
	mux := http.NewServeMux()
	handler.AttachHandlers(a, mux, tmpl)
	newPassword := "foobarfoobar"

	// Account Recovery
	request := httptest.NewRequest(http.MethodGet, "/account-recovery", nil)
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	result := response.Result()
	assert.Equal(t, http.StatusOK, result.StatusCode)
	body, err := io.ReadAll(result.Body)
	assert.Nil(t, err)
	assert.Empty(t, string(body))
	cookies := result.Cookies()
	assert.Equal(t, 1, len(cookies))
	assert.Equal(t, authgo.SESSION_ACCOUNT_RECOVERY_COOKIE, cookies[0].Name)
	values := url.Values{}
	values.Add("email", authtest.TEST_EMAIL)
	reader := strings.NewReader(values.Encode())
	request = httptest.NewRequest(http.MethodPost, "/account-recovery", reader)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(cookies[0])
	response = httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	result = response.Result()
	assert.Equal(t, http.StatusFound, result.StatusCode)
	u, err := result.Location()
	assert.Nil(t, err)
	assert.Equal(t, "/account-recovery-verification", u.String())

	// Account Recovery Verification
	request = httptest.NewRequest(http.MethodGet, "/account-recovery-verification", nil)
	request.AddCookie(cookies[0])
	response = httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	result = response.Result()
	assert.Equal(t, http.StatusOK, result.StatusCode)
	body, err = io.ReadAll(result.Body)
	assert.Nil(t, err)
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
	assert.Equal(t, authgo.SESSION_SIGN_IN_COOKIE, cookies[0].Name)
	u, err = result.Location()
	assert.Nil(t, err)
	assert.Equal(t, "/account-password", u.String())

	// Account Password
	request = httptest.NewRequest(http.MethodGet, "/account-password", nil)
	request.AddCookie(cookies[0])
	response = httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	result = response.Result()
	assert.Equal(t, http.StatusOK, result.StatusCode)
	body, err = io.ReadAll(result.Body)
	assert.Nil(t, err)
	assert.Empty(t, string(body))
	cookies = result.Cookies()
	assert.Equal(t, 2, len(cookies))
	assert.Equal(t, authgo.SESSION_SIGN_IN_COOKIE, cookies[0].Name)
	assert.Equal(t, authgo.SESSION_ACCOUNT_PASSWORD_COOKIE, cookies[1].Name)
	values = url.Values{}
	values.Add("password", newPassword)
	values.Add("confirmation", newPassword)
	reader = strings.NewReader(values.Encode())
	request = httptest.NewRequest(http.MethodPost, "/account-password", reader)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(cookies[0])
	request.AddCookie(cookies[1])
	response = httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	result = response.Result()
	assert.Equal(t, http.StatusFound, result.StatusCode)
	cookies = result.Cookies()
	assert.Equal(t, 1, len(cookies))
	assert.Equal(t, authgo.SESSION_SIGN_IN_COOKIE, cookies[0].Name)
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
