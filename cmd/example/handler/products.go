package handler

import (
	"aletheiaware.com/authgo"
	"aletheiaware.com/authgo/cmd/example/model"
	"aletheiaware.com/authgo/redirect"
	"aletheiaware.com/netgo"
	"aletheiaware.com/netgo/handler"
	"html/template"
	"log"
	"net/http"
)

func AttachProductsHandler(m *http.ServeMux, a authgo.Authenticator, p model.ProductManager, ts *template.Template) {
	m.Handle("/products", handler.Log(handler.Compress(Products(a, p, ts))))
}

func Products(a authgo.Authenticator, p model.ProductManager, ts *template.Template) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		account := a.CurrentAccount(w, r)
		if account == nil {
			redirect.SignIn(w, r, r.URL.String())
			return
		}
		ps := p.AllProducts()
		data := struct {
			Live     bool
			Products []*model.Product
		}{
			Live:     netgo.IsLive(),
			Products: ps,
		}
		if err := ts.ExecuteTemplate(w, "products.go.html", data); err != nil {
			log.Println(err)
			return
		}
	})
}
