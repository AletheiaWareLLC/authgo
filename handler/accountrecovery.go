package handler

import (
	"aletheiaware.com/authgo"
	"aletheiaware.com/authgo/redirect"
	"html/template"
	"log"
	"net/http"
	"strings"
)

func AccountRecovery(a authgo.Authenticator, ts *template.Template) http.Handler {
	am := a.AccountManager()
	sm := a.SessionManager()
	ev := a.EmailVerifier()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if a := a.CurrentAccount(w, r); a != nil {
			// Already signed in
			redirect.Account(w, r)
			return
		}
		token, email, _, _, errmsg := authgo.CurrentAccountRecovery(sm, r)
		// log.Println("CurrentAccountRecovery", token, email, username, challenge, errmsg)
		switch r.Method {
		case "GET":
			if token == "" {
				t, err := sm.NewAccountRecovery()
				// log.Println("NewAccountRecovery", t, err)
				if err != nil {
					log.Println(err)
					http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
					return
				}
				token = t
				http.SetCookie(w, authgo.NewAccountRecoveryCookie(token))
			}
			data := struct {
				Email,
				Error string
			}{
				Email: email,
				Error: errmsg,
			}
			if err := ts.ExecuteTemplate(w, "account-recovery.go.html", data); err != nil {
				log.Println(err)
				return
			}
		case "POST":
			if token == "" {
				redirect.AccountRecovery(w, r)
				return
			}
			sm.SetAccountRecoveryError(token, "")

			email := strings.TrimSpace(r.FormValue("email"))

			if err := sm.SetAccountRecoveryEmail(token, email); err != nil {
				log.Println(err)
				sm.SetAccountRecoveryError(token, err.Error())
				redirect.AccountRecovery(w, r)
				return
			}

			// Check valid email
			if err := authgo.ValidateEmail(email); err != nil {
				log.Println(err)
				sm.SetAccountRecoveryError(token, err.Error())
				redirect.AccountRecovery(w, r)
				return
			}

			// Get username associated with email
			username, err := am.Username(email)
			if err != nil {
				log.Println(err)
				sm.SetAccountRecoveryError(token, err.Error())
				redirect.AccountRecovery(w, r)
				return
			}

			if err := sm.SetAccountRecoveryUsername(token, username); err != nil {
				log.Println(err)
				sm.SetAccountRecoveryError(token, err.Error())
				redirect.AccountRecovery(w, r)
				return
			}

			code, err := ev.VerifyEmail(email)
			// log.Println("VerifyEmail", code, err)
			if err != nil {
				log.Println(err)
				sm.SetAccountRecoveryError(token, err.Error())
				redirect.AccountRecovery(w, r)
				return
			}
			if err := sm.SetAccountRecoveryChallenge(token, code); err != nil {
				log.Println(err)
				sm.SetAccountRecoveryError(token, err.Error())
				redirect.AccountRecovery(w, r)
				return
			}

			redirect.AccountRecoveryVerification(w, r)
		}
	})
}

func AccountRecoveryVerification(a authgo.Authenticator, ts *template.Template) http.Handler {
	sm := a.SessionManager()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, _, username, challenge, errmsg := authgo.CurrentAccountRecovery(sm, r)
		// log.Println("CurrentAccountRecovery", token, email, username, challenge, errmsg)
		if token == "" {
			redirect.AccountRecovery(w, r)
			return
		}
		switch r.Method {
		case "GET":
			data := struct {
				Username,
				Error string
			}{
				Username: username,
				Error:    errmsg,
			}
			if err := ts.ExecuteTemplate(w, "account-recovery-verification.go.html", data); err != nil {
				log.Println(err)
				return
			}
		case "POST":
			sm.SetAccountRecoveryError(token, "")

			if strings.TrimSpace(r.FormValue("verification")) != challenge {
				sm.SetAccountRecoveryError(token, authgo.ErrIncorrectEmailVerification.Error())
				redirect.AccountRecoveryVerification(w, r)
				return
			}

			token, err := sm.NewSignIn(username)
			// log.Println("NewSignIn", token, err)
			if err != nil {
				log.Println(err)
				http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
				return
			}

			http.SetCookie(w, authgo.NewSignInCookie(token))

			redirect.AccountPassword(w, r)
		}
	})
}
