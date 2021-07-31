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

func AttachProductHandler(m *http.ServeMux, a authgo.Authenticator, p model.ProductManager, ts *template.Template) {
	m.Handle("/product", handler.Log(Product(a, p, ts)))
}

func Product(a authgo.Authenticator, p model.ProductManager, ts *template.Template) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		account := a.CurrentAccount(w, r)
		if account == nil {
			redirect.SignIn(w, r)
			return
		}
		p := p.Product(r.FormValue("id"))
		if p == nil {
			http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
			return
		}
		data := struct {
			Live    bool
			Product *model.Product
		}{
			Live:    netgo.IsLive(),
			Product: p,
		}
		if err := ts.ExecuteTemplate(w, "product.go.html", data); err != nil {
			log.Println(err)
			return
		}
	})
}
