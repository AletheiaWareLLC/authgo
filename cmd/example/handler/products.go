package handler

import (
	"aletheiaware.com/authgo"
	"aletheiaware.com/authgo/cmd/example/model"
	"aletheiaware.com/authgo/redirect"
	"aletheiaware.com/netgo"
	"html/template"
	"log"
	"net/http"
)

func AttachProductsHandler(m *http.ServeMux, a authgo.Authenticator, p model.ProductManager, ts *template.Template) {
	m.Handle("/products", netgo.LoggingHandler(Products(a, p, ts)))
}

func Products(a authgo.Authenticator, p model.ProductManager, ts *template.Template) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		account := a.CurrentAccount(w, r)
		if account == nil {
			redirect.SignIn(w, r)
			return
		}
		ps := p.AllProducts()
		data := struct {
			Products []*model.Product
		}{
			Products: ps,
		}
		if err := ts.ExecuteTemplate(w, "products.go.html", data); err != nil {
			log.Println(err)
			return
		}
	})
}
