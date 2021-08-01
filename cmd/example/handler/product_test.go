package handler_test

import (
	"aletheiaware.com/authgo/authtest"
	"aletheiaware.com/authgo/cmd/example/handler"
	"aletheiaware.com/authgo/cmd/example/model"
	"github.com/stretchr/testify/assert"
	"html/template"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestProduct(t *testing.T) {
	tmpl, err := template.New("product.go.html").Parse(`{{with .Product}}{{.ID}}{{.Name}}{{end}}`)
	assert.Nil(t, err)
	t.Run("Redirects When Not Signed In", func(t *testing.T) {
		auth := authtest.NewAuthenticator(t)
		pm := model.NewInMemoryProductManager()
		mux := http.NewServeMux()
		handler.AttachProductHandler(mux, auth, pm, tmpl)
		request := httptest.NewRequest(http.MethodGet, "/product?id=10", nil)
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		result := response.Result()
		assert.Equal(t, http.StatusFound, result.StatusCode)
		u, err := result.Location()
		assert.Nil(t, err)
		assert.Equal(t, "/sign-in", u.String())
	})
	t.Run("Returns 404 When Signed In and Product Does Not Exist", func(t *testing.T) {
		auth := authtest.NewAuthenticator(t)
		authtest.NewTestAccount(t, auth)
		token, _ := authtest.SignIn(t, auth)
		pm := model.NewInMemoryProductManager()
		mux := http.NewServeMux()
		handler.AttachProductHandler(mux, auth, pm, tmpl)
		request := httptest.NewRequest(http.MethodGet, "/product?id=10", nil)
		request.AddCookie(auth.NewSignInSessionCookie(token))
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		result := response.Result()
		body, err := io.ReadAll(result.Body)
		assert.Nil(t, err)
		assert.Equal(t, http.StatusNotFound, result.StatusCode)
		assert.Equal(t, "Not Found\n", string(body))
	})
	t.Run("Returns 200 When Signed In and Product Exists", func(t *testing.T) {
		auth := authtest.NewAuthenticator(t)
		authtest.NewTestAccount(t, auth)
		token, _ := authtest.SignIn(t, auth)
		pm := model.NewInMemoryProductManager()
		pm.AddProduct(&model.Product{
			ID:   "10",
			Name: "FooBar",
		})
		mux := http.NewServeMux()
		handler.AttachProductHandler(mux, auth, pm, tmpl)
		request := httptest.NewRequest(http.MethodGet, "/product?id=10", nil)
		request.AddCookie(auth.NewSignInSessionCookie(token))
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		result := response.Result()
		body, err := io.ReadAll(result.Body)
		assert.Nil(t, err)
		assert.Equal(t, http.StatusOK, result.StatusCode)
		assert.Equal(t, "10FooBar", string(body))
	})
	t.Run("Redirects When Signed Out", func(t *testing.T) {
		auth := authtest.NewAuthenticator(t)
		authtest.NewTestAccount(t, auth)
		token, _ := authtest.SignIn(t, auth)
		pm := model.NewInMemoryProductManager()
		pm.AddProduct(&model.Product{
			ID:   "10",
			Name: "FooBar",
		})
		mux := http.NewServeMux()
		handler.AttachProductHandler(mux, auth, pm, tmpl)
		request := httptest.NewRequest(http.MethodGet, "/product?id=10", nil)
		request.AddCookie(auth.NewSignInSessionCookie(token))
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		result := response.Result()
		assert.Equal(t, http.StatusOK, result.StatusCode)
		authtest.SignOut(t, auth, token)
		response = httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		result = response.Result()
		assert.Equal(t, http.StatusFound, result.StatusCode)
		u, err := result.Location()
		assert.Nil(t, err)
		assert.Equal(t, "/sign-in", u.String())
	})
}
