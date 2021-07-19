package main

import (
	"aletheiaware.com/authgo"
	"aletheiaware.com/netgo"
	"html/template"
	"io/fs"
	"log"
	"net/http"
)

func AttachHealthHandler(m *http.ServeMux) {
	m.Handle("/health", netgo.LoggingHandler(HealthHandler()))
}

func AttachStaticHandler(m *http.ServeMux, fs fs.FS) {
	m.Handle("/static/", netgo.LoggingHandler(http.StripPrefix("/static/", http.FileServer(http.FS(fs)))))
}

func AttachProductsHandler(m *http.ServeMux, a authgo.Authenticator, p ProductManager, ts *template.Template) {
	m.Handle("/products", netgo.LoggingHandler(ProductsHandler(a, p, ts)))
}

func AttachProductHandler(m *http.ServeMux, a authgo.Authenticator, p ProductManager, ts *template.Template) {
	m.Handle("/product", netgo.LoggingHandler(ProductHandler(a, p, ts)))
}

func AttachIndexHandler(m *http.ServeMux, a authgo.Authenticator, ts *template.Template) {
	m.Handle("/", netgo.LoggingHandler(IndexHandler(a, ts)))
}

func HealthHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}

func IndexHandler(a authgo.Authenticator, ts *template.Template) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data := struct {
			Account *authgo.Account
		}{}
		if account := a.CurrentAccount(w, r); account != nil {
			data.Account = account
		}
		if err := ts.ExecuteTemplate(w, "index.go.html", data); err != nil {
			log.Println(err)
			return
		}
	})
}

func ProductsHandler(a authgo.Authenticator, p ProductManager, ts *template.Template) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		account := a.CurrentAccount(w, r)
		if account == nil {
			authgo.RedirectSignIn(w, r)
			return
		}
		ps := p.AllProducts()
		data := struct {
			Products []*Product
		}{
			Products: ps,
		}
		if err := ts.ExecuteTemplate(w, "products.go.html", data); err != nil {
			log.Println(err)
			return
		}
	})
}

func ProductHandler(a authgo.Authenticator, p ProductManager, ts *template.Template) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		account := a.CurrentAccount(w, r)
		if account == nil {
			authgo.RedirectSignIn(w, r)
			return
		}
		p := p.Product(r.FormValue("id"))
		if p == nil {
			http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
			return
		}
		data := struct {
			Product *Product
		}{
			Product: p,
		}
		if err := ts.ExecuteTemplate(w, "product.go.html", data); err != nil {
			log.Println(err)
			return
		}
	})
}
