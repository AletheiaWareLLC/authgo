package handler_test

import (
	"aletheiaware.com/authgo"
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

func TestProducts(t *testing.T) {
	tmpl, err := template.New("products.go.html").Parse(`<ol>{{range .Products}}<li>{{.ID}}{{.Name}}</li>{{end}}</ol>`)
	assert.Nil(t, err)
	t.Run("Redirects When Not Signed In", func(t *testing.T) {
		a := authtest.NewAuthenticator(t)
		pm := model.NewInMemoryProductManager()
		mux := http.NewServeMux()
		handler.AttachProductsHandler(mux, a, pm, tmpl)
		request := httptest.NewRequest(http.MethodGet, "/products", nil)
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		result := response.Result()
		assert.Equal(t, http.StatusFound, result.StatusCode)
		u, err := result.Location()
		assert.Nil(t, err)
		assert.Equal(t, "/sign-in", u.String())
	})
	t.Run("Returns 200 When Signed In", func(t *testing.T) {
		a := authtest.NewAuthenticator(t)
		authtest.NewTestAccount(t, a)
		token, _ := authtest.SignIn(t, a)
		pm := model.NewInMemoryProductManager()
		mux := http.NewServeMux()
		handler.AttachProductsHandler(mux, a, pm, tmpl)
		request := httptest.NewRequest(http.MethodGet, "/products", nil)
		request.AddCookie(authgo.NewSignInSessionCookie(token))
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		result := response.Result()
		assert.Equal(t, http.StatusOK, result.StatusCode)
		cookies := result.Cookies()
		assert.Equal(t, 1, len(cookies))
		assert.Equal(t, authgo.COOKIE_SIGN_IN, cookies[0].Name)
		body, err := io.ReadAll(result.Body)
		assert.Nil(t, err)
		assert.Equal(t, "<ol></ol>", string(body))

		pm.AddProduct(&model.Product{
			ID:   "10",
			Name: "FooBar",
		})
		request = httptest.NewRequest(http.MethodGet, "/products", nil)
		request.AddCookie(cookies[0])
		response = httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		result = response.Result()
		assert.Equal(t, http.StatusOK, result.StatusCode)
		body, err = io.ReadAll(result.Body)
		assert.Nil(t, err)
		assert.Equal(t, "<ol><li>10FooBar</li></ol>", string(body))
	})
	t.Run("Redirects When Signed Out", func(t *testing.T) {
		a := authtest.NewAuthenticator(t)
		authtest.NewTestAccount(t, a)
		token, _ := authtest.SignIn(t, a)
		pm := model.NewInMemoryProductManager()
		mux := http.NewServeMux()
		handler.AttachProductsHandler(mux, a, pm, tmpl)
		request := httptest.NewRequest(http.MethodGet, "/products", nil)
		request.AddCookie(authgo.NewSignInSessionCookie(token))
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		result := response.Result()
		assert.Equal(t, http.StatusOK, result.StatusCode)

		authtest.SignOut(t, a, token)

		request = httptest.NewRequest(http.MethodGet, "/products", nil)
		response = httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		result = response.Result()
		assert.Equal(t, http.StatusFound, result.StatusCode)
		u, err := result.Location()
		assert.Nil(t, err)
		assert.Equal(t, "/sign-in", u.String())
	})
}
