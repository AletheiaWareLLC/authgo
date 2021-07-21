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
	"testing"
)

func TestSignOut(t *testing.T) {
	tmpl, err := template.New("sign-out.go.html").Parse(`{{.Error}}`)
	assert.Nil(t, err)
	t.Run("Returns 200 When Signed In", func(t *testing.T) {
		a := authtest.NewAuthenticator(t)
		authtest.NewTestAccount(t, a)
		token, _ := authtest.SignIn(t, a)
		mux := http.NewServeMux()
		handler.AttachHandlers(a, mux, tmpl)
		request := httptest.NewRequest(http.MethodGet, "/sign-out", nil)
		request.AddCookie(authgo.NewSignInCookie(token))
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		result := response.Result()
		assert.Equal(t, http.StatusOK, result.StatusCode)
		body, err := io.ReadAll(result.Body)
		assert.Nil(t, err)
		assert.Empty(t, string(body))
	})
	t.Run("Redirects After Sign Out", func(t *testing.T) {
		a := authtest.NewAuthenticator(t)
		authtest.NewTestAccount(t, a)
		token, _ := authtest.SignIn(t, a)
		mux := http.NewServeMux()
		handler.AttachHandlers(a, mux, tmpl)
		request := httptest.NewRequest(http.MethodPost, "/sign-out", nil)
		request.AddCookie(authgo.NewSignInCookie(token))
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		result := response.Result()
		assert.Equal(t, http.StatusFound, result.StatusCode)
		u, err := result.Location()
		assert.Nil(t, err)
		assert.Equal(t, "/", u.String())
		username, authenticated, errmsg, ok := a.SessionManager().LookupSignIn(token)
		assert.Equal(t, username, authtest.TEST_USERNAME)
		assert.False(t, authenticated)
		assert.Empty(t, errmsg)
		assert.True(t, ok)
	})
	t.Run("Redirects When Not Signed In", func(t *testing.T) {
		a := authtest.NewAuthenticator(t)
		mux := http.NewServeMux()
		handler.AttachHandlers(a, mux, tmpl)
		request := httptest.NewRequest(http.MethodGet, "/sign-out", nil)
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		result := response.Result()
		assert.Equal(t, http.StatusFound, result.StatusCode)
		u, err := result.Location()
		assert.Nil(t, err)
		assert.Equal(t, "/", u.String())
	})
}
