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

func AttachAccountDeactivateHandler(m *http.ServeMux, a authgo.Authenticator, ts *template.Template) {
	m.Handle("/account-deactivate", handler.Log(AccountDeactivate(a, ts)))
}

func AccountDeactivate(a authgo.Authenticator, ts *template.Template) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		account := a.CurrentAccount(w, r)
		if account == nil {
			redirect.SignIn(w, r, r.URL.String())
			return
		}
		data := &AccountDeactivateData{
			Live:    netgo.IsLive(),
			Account: account,
		}
		switch r.Method {
		case "GET":
			executeAccountDeactiveTemplate(w, ts, data)
		case "POST":
			if err := a.DeactivateAccount(account); err != nil {
				log.Println(err)
				data.Error = err.Error()
				executeAccountDeactiveTemplate(w, ts, data)
				return
			}

			redirect.Index(w, r)
		}
	})
}

func executeAccountDeactiveTemplate(w http.ResponseWriter, ts *template.Template, data *AccountDeactivateData) {
	if err := ts.ExecuteTemplate(w, "account-deactivate.go.html", data); err != nil {
		log.Println(err)
	}
}

type AccountDeactivateData struct {
	Live    bool
	Account *authgo.Account
	Error   string
}
