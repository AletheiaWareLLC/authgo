package handler

import (
	"aletheiaware.com/authgo"
	"aletheiaware.com/authgo/redirect"
	"aletheiaware.com/netgo"
	"aletheiaware.com/netgo/handler"
	"html/template"
	"log"
	"net/http"
	"strings"
)

func AttachAccountPasswordHandler(m *http.ServeMux, a authgo.Authenticator, ts *template.Template) {
	m.Handle("/account-password", handler.Log(AccountPassword(a, ts)))
}

func AccountPassword(a authgo.Authenticator, ts *template.Template) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		account := a.CurrentAccount(w, r)
		if account == nil {
			redirect.SignIn(w, r)
			return
		}
		token, username, errmsg := a.CurrentAccountPasswordSession(r)
		// log.Println("CurrentAccountPasswordSession", token, username, errmsg)
		switch r.Method {
		case "GET":
			if token == "" {
				t, err := a.NewAccountPasswordSession(account.Username)
				// log.Println("NewAccountPasswordSession", t, err)
				if err != nil {
					log.Println(err)
					http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
					return
				}
				token = t
				http.SetCookie(w, a.NewAccountPasswordSessionCookie(token))
			}
			data := struct {
				Live  bool
				Error string
			}{
				Live:  netgo.IsLive(),
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

			password := []byte(strings.TrimSpace(r.FormValue("password")))
			confirmation := []byte(strings.TrimSpace(r.FormValue("confirmation")))

			if err := accountPassword(a, username, password, confirmation); err != nil {
				log.Println(err)
				a.SetAccountPasswordSessionError(token, err.Error())
				redirect.AccountPassword(w, r)
				return
			}
			a.SetAccountPasswordSessionError(token, "")

			redirect.Account(w, r)
		}
	})
}

func accountPassword(a authgo.Authenticator, username string, password, confirmation []byte) error {
	// Check valid password and matching confirm
	if err := authgo.ValidatePassword(password); err != nil {
		return err
	}
	if err := authgo.MatchPasswords(password, confirmation); err != nil {
		return err
	}

	if err := a.ChangePassword(username, password); err != nil {
		return err
	}

	return nil
}
