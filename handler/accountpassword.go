package handler

import (
	"aletheiaware.com/authgo"
	"aletheiaware.com/authgo/redirect"
	"html/template"
	"log"
	"net/http"
	"strings"
)

func AccountPassword(a authgo.Authenticator, ts *template.Template) http.Handler {
	am := a.AccountManager()
	sm := a.SessionManager()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		account := a.CurrentAccount(w, r)
		if account == nil {
			redirect.SignIn(w, r)
			return
		}
		token, username, errmsg := authgo.CurrentAccountPassword(sm, r)
		// log.Println("CurrentAccountPassword", token, username, errmsg)
		switch r.Method {
		case "GET":
			if token == "" {
				t, err := sm.NewAccountPassword(account.Username)
				// log.Println("NewAccountPassword", t, err)
				if err != nil {
					log.Println(err)
					http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
					return
				}
				token = t
				http.SetCookie(w, authgo.NewAccountPasswordCookie(token))
			}
			data := struct {
				Error string
			}{
				Error: errmsg,
			}
			if err := ts.ExecuteTemplate(w, "account-password.go.html", data); err != nil {
				log.Println(err)
				return
			}
		case "POST":
			if token == "" {
				redirect.AccountPassword(w, r)
				return
			}
			sm.SetAccountPasswordError(token, "")

			password := []byte(strings.TrimSpace(r.FormValue("password")))
			confirmation := []byte(strings.TrimSpace(r.FormValue("confirmation")))

			// Check valid password and matching confirm
			if err := authgo.ValidatePassword(password); err != nil {
				log.Println(err)
				sm.SetAccountPasswordError(token, err.Error())
				redirect.AccountPassword(w, r)
				return
			}
			if err := authgo.MatchPasswords(password, confirmation); err != nil {
				log.Println(err)
				sm.SetAccountPasswordError(token, err.Error())
				redirect.AccountPassword(w, r)
				return
			}

			if err := am.ChangePassword(username, password); err != nil {
				log.Println(err)
				sm.SetAccountPasswordError(token, err.Error())
				redirect.AccountPassword(w, r)
				return
			}

			redirect.Account(w, r)
		}
	})
}
