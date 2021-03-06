package handler_test

import (
	"aletheiaware.com/authgo/authtest"
	"aletheiaware.com/authgo/cmd/example/handler"
	"github.com/stretchr/testify/assert"
	"html/template"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestIndex(t *testing.T) {
	tmpl, err := template.New("index.go.html").Parse(`{{with .Account}}{{.Username}}{{end}}`)
	assert.Nil(t, err)
	t.Run("Returns 200 When Signed In", func(t *testing.T) {
		auth := authtest.NewAuthenticator(t)
		authtest.NewTestAccount(t, auth)
		token, _ := authtest.SignIn(t, auth)
		mux := http.NewServeMux()
		handler.AttachIndexHandler(mux, auth, tmpl)
		request := httptest.NewRequest(http.MethodGet, "/", nil)
		request.AddCookie(auth.NewSignInSessionCookie(token))
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		result := response.Result()
		body, err := io.ReadAll(result.Body)
		assert.Nil(t, err)
		assert.Equal(t, http.StatusOK, result.StatusCode)
		assert.Equal(t, authtest.TEST_USERNAME, string(body))
	})
	t.Run("Returns 200 When Not Signed In", func(t *testing.T) {
		auth := authtest.NewAuthenticator(t)
		mux := http.NewServeMux()
		handler.AttachIndexHandler(mux, auth, tmpl)
		request := httptest.NewRequest(http.MethodGet, "/", nil)
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		result := response.Result()
		body, err := io.ReadAll(result.Body)
		assert.Nil(t, err)
		assert.Equal(t, http.StatusOK, result.StatusCode)
		assert.Empty(t, string(body))
	})
}
