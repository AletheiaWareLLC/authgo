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
	"strings"
	"testing"
)

func SignIn(t *testing.T, a func(*testing.T) authgo.Authenticator) {
	tmpl, err := template.New("sign-in.go.html").Parse(`{{.Error}}`)
	assert.Nil(t, err)
	t.Run("Redirects When Signed In", func(t *testing.T) {
		auth := a(t)
		authtest.NewTestAccount(t, auth)
		token, _ := authtest.SignIn(t, auth)
		mux := http.NewServeMux()
		handler.AttachSignInHandler(mux, auth, tmpl)
		request := httptest.NewRequest(http.MethodGet, "/sign-in", nil)
		request.AddCookie(authgo.NewSignInSessionCookie(token))
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		result := response.Result()
		assert.Equal(t, http.StatusFound, result.StatusCode)
		u, err := result.Location()
		assert.Nil(t, err)
		assert.Equal(t, "/account", u.String())
	})
	t.Run("Returns 200 When Not Signed In", func(t *testing.T) {
		auth := a(t)
		mux := http.NewServeMux()
		handler.AttachSignInHandler(mux, auth, tmpl)
		request := httptest.NewRequest(http.MethodGet, "/sign-in", nil)
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		result := response.Result()
		assert.Equal(t, http.StatusOK, result.StatusCode)
		body, err := io.ReadAll(result.Body)
		assert.Nil(t, err)
		assert.Empty(t, string(body))
		cookies := result.Cookies()
		assert.Equal(t, 1, len(cookies))
		assert.Equal(t, authgo.COOKIE_SIGN_IN, cookies[0].Name)
	})
	t.Run("Redirects When Credentials Are Correct", func(t *testing.T) {
		auth := a(t)
		acc := authtest.NewTestAccount(t, auth)
		assert.Nil(t, auth.SetEmailVerified(acc.Email, true))
		mux := http.NewServeMux()
		handler.AttachSignInHandler(mux, auth, tmpl)
		request := httptest.NewRequest(http.MethodGet, "/sign-in", nil)
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		result := response.Result()
		assert.Equal(t, http.StatusOK, result.StatusCode)
		body, err := io.ReadAll(result.Body)
		assert.Nil(t, err)
		assert.Empty(t, string(body))
		cookies := result.Cookies()
		assert.Equal(t, 1, len(cookies))
		assert.Equal(t, authgo.COOKIE_SIGN_IN, cookies[0].Name)
		reader := strings.NewReader("username=" + authtest.TEST_USERNAME + "&password=" + authtest.TEST_PASSWORD)
		request = httptest.NewRequest(http.MethodPost, "/sign-in", reader)
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		request.AddCookie(cookies[0])
		response = httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		result = response.Result()
		assert.Equal(t, http.StatusFound, result.StatusCode)
		body, err = io.ReadAll(result.Body)
		assert.Nil(t, err)
		u, err := result.Location()
		assert.Nil(t, err)
		assert.Equal(t, "/account", u.String())
	})
	t.Run("Redirects When Post Requested Before Get", func(t *testing.T) {
		auth := a(t)
		mux := http.NewServeMux()
		handler.AttachSignInHandler(mux, auth, tmpl)
		reader := strings.NewReader("username=" + authtest.TEST_USERNAME + "&password=" + authtest.TEST_PASSWORD)
		request := httptest.NewRequest(http.MethodPost, "/sign-in", reader)
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		result := response.Result()
		assert.Equal(t, http.StatusFound, result.StatusCode)
		u, err := result.Location()
		assert.Nil(t, err)
		assert.Equal(t, "/sign-in", u.String())
	})
	t.Run("Redirects When Username Is Unregistered", func(t *testing.T) {
		auth := a(t)
		mux := http.NewServeMux()
		handler.AttachSignInHandler(mux, auth, tmpl)
		request := httptest.NewRequest(http.MethodGet, "/sign-in", nil)
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		result := response.Result()
		assert.Equal(t, http.StatusOK, result.StatusCode)
		body, err := io.ReadAll(result.Body)
		assert.Nil(t, err)
		assert.Empty(t, string(body))
		cookies := result.Cookies()
		assert.Equal(t, 1, len(cookies))
		assert.Equal(t, authgo.COOKIE_SIGN_IN, cookies[0].Name)
		reader := strings.NewReader("username=foobar&password=" + authtest.TEST_PASSWORD)
		request = httptest.NewRequest(http.MethodPost, "/sign-in", reader)
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		request.AddCookie(cookies[0])
		response = httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		result = response.Result()
		assert.Equal(t, http.StatusFound, result.StatusCode)
		u, err := result.Location()
		assert.Nil(t, err)
		assert.Equal(t, "/sign-in", u.String())

		// Subsequent Get request should show error
		request = httptest.NewRequest(http.MethodGet, "/sign-in", nil)
		request.AddCookie(cookies[0])
		response = httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		result = response.Result()
		assert.Equal(t, http.StatusOK, result.StatusCode)
		body, err = io.ReadAll(result.Body)
		assert.Nil(t, err)
		assert.Equal(t, authgo.ErrIncorrectCredentials.Error(), string(body))
	})
	t.Run("Redirects When Password Is Wrong", func(t *testing.T) {
		auth := a(t)
		authtest.NewTestAccount(t, auth)
		mux := http.NewServeMux()
		handler.AttachSignInHandler(mux, auth, tmpl)
		request := httptest.NewRequest(http.MethodGet, "/sign-in", nil)
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		result := response.Result()
		assert.Equal(t, http.StatusOK, result.StatusCode)
		body, err := io.ReadAll(result.Body)
		assert.Nil(t, err)
		assert.Empty(t, string(body))
		cookies := result.Cookies()
		assert.Equal(t, 1, len(cookies))
		assert.Equal(t, authgo.COOKIE_SIGN_IN, cookies[0].Name)
		reader := strings.NewReader("username=" + authtest.TEST_USERNAME + "&password=foobarfoobar")
		request = httptest.NewRequest(http.MethodPost, "/sign-in", reader)
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		request.AddCookie(cookies[0])
		response = httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		result = response.Result()
		assert.Equal(t, http.StatusFound, result.StatusCode)
		u, err := result.Location()
		assert.Nil(t, err)
		assert.Equal(t, "/sign-in", u.String())

		// Subsequent Get request should show error
		request = httptest.NewRequest(http.MethodGet, "/sign-in", nil)
		request.AddCookie(cookies[0])
		response = httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		result = response.Result()
		assert.Equal(t, http.StatusOK, result.StatusCode)
		body, err = io.ReadAll(result.Body)
		assert.Nil(t, err)
		assert.Equal(t, authgo.ErrIncorrectCredentials.Error(), string(body))
	})
	t.Run("Redirects When Email Is Not Verified", func(t *testing.T) {
		auth := a(t)
		authtest.NewTestAccount(t, auth)
		mux := http.NewServeMux()
		handler.AttachSignInHandler(mux, auth, tmpl)
		request := httptest.NewRequest(http.MethodGet, "/sign-in", nil)
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		result := response.Result()
		assert.Equal(t, http.StatusOK, result.StatusCode)
		body, err := io.ReadAll(result.Body)
		assert.Nil(t, err)
		assert.Empty(t, string(body))
		cookies := result.Cookies()
		assert.Equal(t, 1, len(cookies))
		assert.Equal(t, authgo.COOKIE_SIGN_IN, cookies[0].Name)
		reader := strings.NewReader("username=" + authtest.TEST_USERNAME + "&password=" + authtest.TEST_PASSWORD)
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
		cookies = result.Cookies()
		assert.Equal(t, 1, len(cookies))
		assert.Equal(t, authgo.COOKIE_SIGN_UP, cookies[0].Name)
		u, err := result.Location()
		assert.Nil(t, err)
		assert.Equal(t, "/sign-up-verification", u.String())
	})
}
