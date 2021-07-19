package main_test

import (
	"aletheiaware.com/authgo"
	"aletheiaware.com/authgo/authtest"
	"aletheiaware.com/authgo/cmd/example"
	"github.com/stretchr/testify/assert"
	"html/template"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/fstest"
)

func TestHealth(t *testing.T) {
	t.Run("Returns 200", func(t *testing.T) {
		mux := http.NewServeMux()
		main.AttachHealthHandler(mux)
		request := httptest.NewRequest(http.MethodGet, "/health", nil)
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		result := response.Result()
		body, err := io.ReadAll(result.Body)
		assert.Nil(t, err)
		assert.Equal(t, http.StatusOK, result.StatusCode)
		assert.Equal(t, "", string(body))
	})
}

func TestStatic(t *testing.T) {
	mux := http.NewServeMux()
	fs := fstest.MapFS{
		"exists": {
			Data: []byte("hello, world"),
		},
	}
	main.AttachStaticHandler(mux, fs)
	t.Run("Returns 200 When File Exists", func(t *testing.T) {
		request := httptest.NewRequest(http.MethodGet, "/static/exists", nil)
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		result := response.Result()
		body, err := io.ReadAll(result.Body)
		assert.Nil(t, err)
		assert.Equal(t, http.StatusOK, result.StatusCode)
		assert.Equal(t, "hello, world", string(body))
	})
	t.Run("Returns 404 When File Does Not Exist", func(t *testing.T) {
		request := httptest.NewRequest(http.MethodGet, "/static/does-not-exist", nil)
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		result := response.Result()
		body, err := io.ReadAll(result.Body)
		assert.Nil(t, err)
		assert.Equal(t, http.StatusNotFound, result.StatusCode)
		assert.Equal(t, "404 page not found\n", string(body))
	})
}

func TestIndex(t *testing.T) {
	tmpl, err := template.New("index.go.html").Parse(`{{with .Account}}Hello {{.Username}}{{end}}`)
	assert.Nil(t, err)
	t.Run("Returns 200 When Signed In", func(t *testing.T) {
		a := authtest.NewAuthenticator(t)
		authtest.NewTestAccount(t, a)
		id, session := authtest.SignIn(t, a)
		mux := http.NewServeMux()
		main.AttachIndexHandler(mux, a, tmpl)
		request := httptest.NewRequest(http.MethodGet, "/", nil)
		request.AddCookie(session.Cookie(id))
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		result := response.Result()
		body, err := io.ReadAll(result.Body)
		assert.Nil(t, err)
		assert.Equal(t, http.StatusOK, result.StatusCode)
		assert.Equal(t, "Hello "+authtest.TEST_USERNAME, string(body))
	})
	t.Run("Returns 200 When Not Signed In", func(t *testing.T) {
		a := authtest.NewAuthenticator(t)
		mux := http.NewServeMux()
		main.AttachIndexHandler(mux, a, tmpl)
		request := httptest.NewRequest(http.MethodGet, "/", nil)
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		result := response.Result()
		body, err := io.ReadAll(result.Body)
		assert.Nil(t, err)
		assert.Equal(t, http.StatusOK, result.StatusCode)
		assert.Equal(t, "", string(body))
	})
}

func TestProducts(t *testing.T) {
	tmpl, err := template.New("products.go.html").Parse(`<ol>{{range .Products}}<li>{{.ID}}{{.Name}}</li>{{end}}</ol>`)
	assert.Nil(t, err)
	t.Run("Redirects When Not Signed In", func(t *testing.T) {
		a := authtest.NewAuthenticator(t)
		pm := main.NewInMemoryProductManager()
		mux := http.NewServeMux()
		main.AttachProductsHandler(mux, a, pm, tmpl)
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
		id, session := authtest.SignIn(t, a)
		pm := main.NewInMemoryProductManager()
		mux := http.NewServeMux()
		main.AttachProductsHandler(mux, a, pm, tmpl)
		request := httptest.NewRequest(http.MethodGet, "/products", nil)
		request.AddCookie(session.Cookie(id))
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		result := response.Result()
		assert.Equal(t, http.StatusOK, result.StatusCode)
		cookies := result.Cookies()
		assert.Equal(t, 1, len(cookies))
		assert.Equal(t, authgo.SESSION_SIGN_IN_COOKIE, cookies[0].Name)
		body, err := io.ReadAll(result.Body)
		assert.Nil(t, err)
		assert.Equal(t, "<ol></ol>", string(body))

		pm.AddProduct(&main.Product{
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
		id, session := authtest.SignIn(t, a)
		pm := main.NewInMemoryProductManager()
		mux := http.NewServeMux()
		main.AttachProductsHandler(mux, a, pm, tmpl)
		request := httptest.NewRequest(http.MethodGet, "/products", nil)
		request.AddCookie(session.Cookie(id))
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		result := response.Result()
		assert.Equal(t, http.StatusOK, result.StatusCode)

		authtest.SignOut(t, a, id)

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

func TestProduct(t *testing.T) {
	tmpl, err := template.New("product.go.html").Parse(`{{with .Product}}{{.ID}}{{.Name}}{{end}}`)
	assert.Nil(t, err)
	t.Run("Redirects When Not Signed In", func(t *testing.T) {
		a := authtest.NewAuthenticator(t)
		pm := main.NewInMemoryProductManager()
		mux := http.NewServeMux()
		main.AttachProductHandler(mux, a, pm, tmpl)
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
		a := authtest.NewAuthenticator(t)
		authtest.NewTestAccount(t, a)
		id, session := authtest.SignIn(t, a)
		pm := main.NewInMemoryProductManager()
		mux := http.NewServeMux()
		main.AttachProductHandler(mux, a, pm, tmpl)
		request := httptest.NewRequest(http.MethodGet, "/product?id=10", nil)
		request.AddCookie(session.Cookie(id))
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		result := response.Result()
		body, err := io.ReadAll(result.Body)
		assert.Nil(t, err)
		assert.Equal(t, http.StatusNotFound, result.StatusCode)
		assert.Equal(t, "Not Found\n", string(body))
	})
	t.Run("Returns 200 When Signed In and Product Exists", func(t *testing.T) {
		a := authtest.NewAuthenticator(t)
		authtest.NewTestAccount(t, a)
		id, session := authtest.SignIn(t, a)
		pm := main.NewInMemoryProductManager()
		pm.AddProduct(&main.Product{
			ID:   "10",
			Name: "FooBar",
		})
		mux := http.NewServeMux()
		main.AttachProductHandler(mux, a, pm, tmpl)
		request := httptest.NewRequest(http.MethodGet, "/product?id=10", nil)
		request.AddCookie(session.Cookie(id))
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		result := response.Result()
		body, err := io.ReadAll(result.Body)
		assert.Nil(t, err)
		assert.Equal(t, http.StatusOK, result.StatusCode)
		assert.Equal(t, "10FooBar", string(body))
	})
	t.Run("Redirects When Signed Out", func(t *testing.T) {
		a := authtest.NewAuthenticator(t)
		authtest.NewTestAccount(t, a)
		id, session := authtest.SignIn(t, a)
		pm := main.NewInMemoryProductManager()
		pm.AddProduct(&main.Product{
			ID:   "10",
			Name: "FooBar",
		})
		mux := http.NewServeMux()
		main.AttachProductHandler(mux, a, pm, tmpl)
		request := httptest.NewRequest(http.MethodGet, "/product?id=10", nil)
		request.AddCookie(session.Cookie(id))
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		result := response.Result()
		assert.Equal(t, http.StatusOK, result.StatusCode)
		authtest.SignOut(t, a, id)
		response = httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		result = response.Result()
		assert.Equal(t, http.StatusFound, result.StatusCode)
		u, err := result.Location()
		assert.Nil(t, err)
		assert.Equal(t, "/sign-in", u.String())
	})
}
