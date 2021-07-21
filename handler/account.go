package handler

import (
	"aletheiaware.com/authgo"
	"aletheiaware.com/authgo/redirect"
	"html/template"
	"log"
	"net/http"
)

func Account(a authgo.Authenticator, ts *template.Template) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		account := a.CurrentAccount(w, r)
		if account == nil {
			redirect.SignIn(w, r)
			return
		}
		data := struct {
			Account *authgo.Account
		}{
			Account: account,
		}
		if err := ts.ExecuteTemplate(w, "account.go.html", data); err != nil {
			log.Println(err)
			return
		}
	})
}
