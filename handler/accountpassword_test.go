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
)

func TestAccountPassword(t *testing.T) {
	tmpl, err := template.New("account-password.go.html").Parse(`{{.Error}}`)
	assert.Nil(t, err)
	t.Run("Returns 200 When Signed In", func(t *testing.T) {
		a := authtest.NewAuthenticator(t)
		authtest.NewTestAccount(t, a)
		token, _ := authtest.SignIn(t, a)
		mux := http.NewServeMux()
		handler.AttachHandlers(a, mux, tmpl)
		request := httptest.NewRequest(http.MethodGet, "/account-password", nil)
		request.AddCookie(authgo.NewSignInCookie(token))
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		result := response.Result()
		assert.Equal(t, http.StatusOK, result.StatusCode)
		body, err := io.ReadAll(result.Body)
		assert.Nil(t, err)
		assert.Empty(t, string(body))
	})
	t.Run("Redirects When Not Signed In", func(t *testing.T) {
		a := authtest.NewAuthenticator(t)
		mux := http.NewServeMux()
		handler.AttachHandlers(a, mux, tmpl)
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
		a := authtest.NewAuthenticator(t)
		authtest.NewTestAccount(t, a)
		token, _ := authtest.SignIn(t, a)
		mux := http.NewServeMux()
		handler.AttachHandlers(a, mux, tmpl)
		request := httptest.NewRequest(http.MethodGet, "/account-password", nil)
		request.AddCookie(authgo.NewSignInCookie(token))
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		result := response.Result()
		assert.Equal(t, http.StatusOK, result.StatusCode)
		body, err := io.ReadAll(result.Body)
		assert.Nil(t, err)
		cookies := result.Cookies()
		assert.Equal(t, 2, len(cookies))
		assert.Equal(t, authgo.SESSION_SIGN_IN_COOKIE, cookies[0].Name)
		assert.Equal(t, authgo.SESSION_ACCOUNT_PASSWORD_COOKIE, cookies[1].Name)
		assert.Empty(t, string(body))
		values := url.Values{}
		values.Add("password", authtest.TEST_PASSWORD)
		values.Add("confirmation", authtest.TEST_PASSWORD)
		reader := strings.NewReader(values.Encode())
		request = httptest.NewRequest(http.MethodPost, "/account-password", reader)
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		request.AddCookie(cookies[0])
		request.AddCookie(cookies[1])
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
				a := authtest.NewAuthenticator(t)
				authtest.NewTestAccount(t, a)
				token, _ := authtest.SignIn(t, a)
				mux := http.NewServeMux()
				handler.AttachHandlers(a, mux, tmpl)
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
				signInCookie := cookies[0]
				accountPasswordCookie := cookies[1]
				assert.Equal(t, authgo.SESSION_SIGN_IN_COOKIE, signInCookie.Name)
				assert.Equal(t, authgo.SESSION_ACCOUNT_PASSWORD_COOKIE, accountPasswordCookie.Name)
				values := url.Values{}
				for k, v := range tt.form {
					values.Add(k, v)
				}
				reader := strings.NewReader(values.Encode())
				request = httptest.NewRequest(http.MethodPost, "/account-password", reader)
				request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				request.AddCookie(cookies[0])
				request.AddCookie(cookies[1])
				response = httptest.NewRecorder()
				mux.ServeHTTP(response, request)
				result = response.Result()
				assert.Equal(t, http.StatusFound, result.StatusCode)
				// Sign In Cookie should get refreshed
				cookies = result.Cookies()
				assert.Equal(t, 1, len(cookies))
				signInCookie = cookies[0]
				assert.Equal(t, authgo.SESSION_SIGN_IN_COOKIE, signInCookie.Name)
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
