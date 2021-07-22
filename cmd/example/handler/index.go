package handler

import (
	"aletheiaware.com/authgo"
	"aletheiaware.com/netgo/handler"
	"html/template"
	"log"
	"net/http"
)

func AttachIndexHandler(m *http.ServeMux, a authgo.Authenticator, ts *template.Template) {
	m.Handle("/", handler.Log(Index(a, ts)))
}

func Index(a authgo.Authenticator, ts *template.Template) http.Handler {
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
