package handler

import (
	"aletheiaware.com/authgo"
	"aletheiaware.com/authgo/redirect"
	"html/template"
	"log"
	"net/http"
)

func SignOut(a authgo.Authenticator, ts *template.Template) http.Handler {
	am := a.AccountManager()
	sm := a.SessionManager()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, username, authenticated, errmsg := authgo.CurrentSignIn(sm, r)
		// log.Println("CurrentSignIn", token, username, authenticated, errmsg)
		if token == "" || username == "" || !authenticated {
			// Not signed in
			redirect.Index(w, r)
			return
		}
		switch r.Method {
		case "GET":
			data := struct {
				Account *authgo.Account
				Error   string
			}{
				Error: errmsg,
			}
			account, err := am.Lookup(username)
			if err == nil {
				data.Account = account
			}
			if err := ts.ExecuteTemplate(w, "sign-out.go.html", data); err != nil {
				log.Println(err)
				return
			}
		case "POST":
			sm.SetSignInError(token, "")
			if err := sm.SetSignInAuthenticated(token, false); err != nil {
				log.Println(err)
			}
			redirect.Index(w, r)
		}
	})
}
