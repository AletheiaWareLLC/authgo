package handler

import (
	"aletheiaware.com/authgo"
	"aletheiaware.com/authgo/redirect"
	"aletheiaware.com/netgo"
	"aletheiaware.com/netgo/handler"
	"html/template"
	"log"
	"net/http"
)

func AttachAccountHandler(m *http.ServeMux, a authgo.Authenticator, ts *template.Template) {
	m.Handle("/account", handler.Log(Account(a, ts)))
}

func Account(a authgo.Authenticator, ts *template.Template) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		account := a.CurrentAccount(w, r)
		if account == nil {
			redirect.SignIn(w, r, r.URL.String())
			return
		}
		data := struct {
			Live    bool
			Account *authgo.Account
		}{
			Live:    netgo.IsLive(),
			Account: account,
		}
		if err := ts.ExecuteTemplate(w, "account.go.html", data); err != nil {
			log.Println(err)
			return
		}
	})
}
