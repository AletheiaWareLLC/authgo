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
)

func AccountPassword(t *testing.T, a func(*testing.T) authgo.Authenticator) {
	tmpl, err := template.New("account-password.go.html").Parse(`{{.Error}}`)
	assert.Nil(t, err)
	t.Run("Returns 200 When Signed In", func(t *testing.T) {
		auth := a(t)
		authtest.NewTestAccount(t, auth)
		token, _ := authtest.SignIn(t, auth)
		mux := http.NewServeMux()
		handler.AttachAccountPasswordHandler(mux, auth, tmpl)
		request := httptest.NewRequest(http.MethodGet, "/account-password", nil)
		request.AddCookie(auth.NewSignInSessionCookie(token))
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		result := response.Result()
		assert.Equal(t, http.StatusOK, result.StatusCode)
		body, err := io.ReadAll(result.Body)
		assert.Nil(t, err)
		assert.Empty(t, string(body))
	})
	t.Run("Redirects When Not Signed In", func(t *testing.T) {
		auth := a(t)
		mux := http.NewServeMux()
		handler.AttachAccountPasswordHandler(mux, auth, tmpl)
		request := httptest.NewRequest(http.MethodGet, "/account-password", nil)
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		result := response.Result()
		assert.Equal(t, http.StatusFound, result.StatusCode)
		u, err := result.Location()
		assert.Nil(t, err)
		assert.Equal(t, "/sign-in", u.String())
	})
	t.Run("Redirects After Password Change", func(t *testing.T) {
		auth := a(t)
		authtest.NewTestAccount(t, auth)
		token, _ := authtest.SignIn(t, auth)
		mux := http.NewServeMux()
		handler.AttachAccountPasswordHandler(mux, auth, tmpl)
		request := httptest.NewRequest(http.MethodGet, "/account-password", nil)
		signInCookie := auth.NewSignInSessionCookie(token)
		request.AddCookie(signInCookie)
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		result := response.Result()
		assert.Equal(t, http.StatusOK, result.StatusCode)
		body, err := io.ReadAll(result.Body)
		assert.Nil(t, err)
		cookies := result.Cookies()
		assert.Equal(t, 1, len(cookies))
		accountPasswordCookie := cookies[0]
		assert.Equal(t, authgo.COOKIE_ACCOUNT_PASSWORD, accountPasswordCookie.Name)
		assert.Empty(t, string(body))
		values := url.Values{}
		values.Add("password", authtest.TEST_PASSWORD)
		values.Add("confirmation", authtest.TEST_PASSWORD)
		reader := strings.NewReader(values.Encode())
		request = httptest.NewRequest(http.MethodPost, "/account-password", reader)
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		request.AddCookie(signInCookie)
		request.AddCookie(cookies[0])
		response = httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		result = response.Result()
		assert.Equal(t, http.StatusFound, result.StatusCode)
		u, err := result.Location()
		assert.Nil(t, err)
		assert.Equal(t, "/account", u.String())
	})
	t.Run("Redirects When Form Data Is Invalid", func(t *testing.T) {
		for name, tt := range map[string]struct {
			form   map[string]string
			result string
		}{
			"Password Too Short": {
				form: map[string]string{
					"password":     "password",
					"confirmation": "password",
				},
				result: authgo.ErrPasswordTooShort.Error(),
			},
			"Passwords Do Not Match": {
				form: map[string]string{
					"password":     authtest.TEST_PASSWORD,
					"confirmation": "1234password",
				},
				result: authgo.ErrPasswordsDoNotMatch.Error(),
			},
		} {
			t.Run(name, func(t *testing.T) {
				auth := a(t)
				authtest.NewTestAccount(t, auth)
				token, _ := authtest.SignIn(t, auth)
				mux := http.NewServeMux()
				handler.AttachAccountPasswordHandler(mux, auth, tmpl)
				request := httptest.NewRequest(http.MethodGet, "/account-password", nil)
				signInCookie := auth.NewSignInSessionCookie(token)
				request.AddCookie(signInCookie)
				response := httptest.NewRecorder()
				mux.ServeHTTP(response, request)
				result := response.Result()
				assert.Equal(t, http.StatusOK, result.StatusCode)
				body, err := io.ReadAll(result.Body)
				assert.Nil(t, err)
				assert.Empty(t, string(body))
				cookies := result.Cookies()
				assert.Equal(t, 1, len(cookies))
				accountPasswordCookie := cookies[0]
				assert.Equal(t, authgo.COOKIE_ACCOUNT_PASSWORD, accountPasswordCookie.Name)
				values := url.Values{}
				for k, v := range tt.form {
					values.Add(k, v)
				}
				reader := strings.NewReader(values.Encode())
				request = httptest.NewRequest(http.MethodPost, "/account-password", reader)
				request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				request.AddCookie(signInCookie)
				request.AddCookie(accountPasswordCookie)
				response = httptest.NewRecorder()
				mux.ServeHTTP(response, request)
				result = response.Result()
				assert.Equal(t, http.StatusFound, result.StatusCode)
				u, err := result.Location()
				assert.Nil(t, err)
				assert.Equal(t, "/account-password", u.String())

				// Subsequent Get request should show error
				request = httptest.NewRequest(http.MethodGet, "/account-password", nil)
				request.AddCookie(signInCookie)
				request.AddCookie(accountPasswordCookie)
				response = httptest.NewRecorder()
				mux.ServeHTTP(response, request)
				result = response.Result()
				assert.Equal(t, http.StatusOK, result.StatusCode)
				body, err = io.ReadAll(result.Body)
				assert.Nil(t, err)
				assert.Equal(t, tt.result, string(body))
			})
		}
	})
}
