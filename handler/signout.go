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

func AttachSignOutHandler(m *http.ServeMux, a authgo.Authenticator, ts *template.Template) {
	m.Handle("/sign-out", handler.Log(SignOut(a, ts)))
}

func SignOut(a authgo.Authenticator, ts *template.Template) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, username, authenticated, errmsg := a.CurrentSignInSession(r)
		// log.Println("CurrentSignInSession", token, username, authenticated, errmsg)
		if token == "" || username == "" || !authenticated {
			// Not signed in
			redirect.Index(w, r)
			return
		}
		switch r.Method {
		case "GET":
			data := struct {
				Live    bool
				Account *authgo.Account
				Error   string
			}{
				Live:  netgo.IsLive(),
				Error: errmsg,
			}
			account, err := a.LookupAccount(username)
			if err == nil {
				data.Account = account
			}
			if err := ts.ExecuteTemplate(w, "sign-out.go.html", data); err != nil {
				log.Println(err)
				return
			}
		case "POST":
			a.SetSignInSessionError(token, "")
			if err := a.SetSignInSessionAuthenticated(token, false); err != nil {
				log.Println(err)
			}
			redirect.Index(w, r)
		}
	})
}
