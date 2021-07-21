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

func TestAccount(t *testing.T) {
	tmpl, err := template.New("account.go.html").Parse(`{{.Account.Username}}`)
	assert.Nil(t, err)
	t.Run("Returns 200 When Signed In", func(t *testing.T) {
		a := authtest.NewAuthenticator(t)
		authtest.NewTestAccount(t, a)
		token, _ := authtest.SignIn(t, a)
		mux := http.NewServeMux()
		handler.AttachHandlers(a, mux, tmpl)
		request := httptest.NewRequest(http.MethodGet, "/account", nil)
		request.AddCookie(authgo.NewSignInCookie(token))
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		result := response.Result()
		assert.Equal(t, http.StatusOK, result.StatusCode)
		body, err := io.ReadAll(result.Body)
		assert.Nil(t, err)
		assert.Equal(t, authtest.TEST_USERNAME, string(body))
	})
	t.Run("Redirects When Not Signed In", func(t *testing.T) {
		a := authtest.NewAuthenticator(t)
		mux := http.NewServeMux()
		handler.AttachHandlers(a, mux, tmpl)
		request := httptest.NewRequest(http.MethodGet, "/account", nil)
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		result := response.Result()
		assert.Equal(t, http.StatusFound, result.StatusCode)
		u, err := result.Location()
		assert.Nil(t, err)
		assert.Equal(t, "/sign-in", u.String())
	})
}
