package handler

import (
	"aletheiaware.com/authgo"
	"aletheiaware.com/authgo/redirect"
	"aletheiaware.com/netgo"
	"aletheiaware.com/netgo/handler"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"strings"
)

func AttachAccountPasswordHandler(m *http.ServeMux, a authgo.Authenticator, ts *template.Template) {
	m.Handle("/account-password", handler.Log(handler.Compress(AccountPassword(a, ts))))
}

func AccountPassword(a authgo.Authenticator, ts *template.Template) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		account := a.CurrentAccount(w, r)
		if account == nil {
			redirect.SignIn(w, r, r.URL.String())
			return
		}
		token, username, errmsg := a.CurrentAccountPasswordSession(r)
		// log.Println("CurrentAccountPasswordSession", token, username, errmsg)
		next, err := url.QueryUnescape(strings.TrimSpace(r.FormValue("next")))
		if err != nil {
			log.Println(err)
			http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
			return
		}
		switch r.Method {
		case "GET":
			data := struct {
				Live  bool
				Error string
				Next  string
			}{
				Live:  netgo.IsLive(),
				Error: errmsg,
				Next:  next,
			}
			if err := ts.ExecuteTemplate(w, "account-password.go.html", data); err != nil {
				log.Println(err)
				return
			}
		case "POST":
			if token == "" {
				username = account.Username
				t, err := a.NewAccountPasswordSession(username)
				// log.Println("NewAccountPasswordSession", t, err)
				if err != nil {
					log.Println(err)
					http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
					return
				}
				token = t
				http.SetCookie(w, a.NewAccountPasswordSessionCookie(token))
			}

			password := []byte(strings.TrimSpace(r.FormValue("password")))
			confirmation := []byte(strings.TrimSpace(r.FormValue("confirmation")))

			if err := accountPassword(a, username, password, confirmation); err != nil {
				log.Println(err)
				a.SetAccountPasswordSessionError(token, err.Error())
				redirect.AccountPassword(w, r, next)
				return
			}
			a.SetAccountPasswordSessionError(token, "")

			if next == "" {
				redirect.Account(w, r)
			} else {
				http.Redirect(w, r, next, http.StatusFound)
			}
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
