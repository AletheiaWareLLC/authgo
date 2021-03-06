package handler

import (
	"aletheiaware.com/authgo"
	"aletheiaware.com/netgo"
	"aletheiaware.com/netgo/handler"
	"html/template"
	"log"
	"net/http"
)

func AttachIndexHandler(m *http.ServeMux, a authgo.Authenticator, ts *template.Template) {
	m.Handle("/", handler.Log(handler.Compress(Index(a, ts))))
}

func Index(a authgo.Authenticator, ts *template.Template) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data := struct {
			Live    bool
			Account *authgo.Account
		}{
			Live: netgo.IsLive(),
		}
		if account := a.CurrentAccount(w, r); account != nil {
			data.Account = account
		}
		if err := ts.ExecuteTemplate(w, "index.go.html", data); err != nil {
			log.Println(err)
			return
		}
	})
}
