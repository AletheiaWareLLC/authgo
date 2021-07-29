package handler

import (
	"aletheiaware.com/authgo"
	"aletheiaware.com/authgo/redirect"
	"aletheiaware.com/netgo/handler"
	"html/template"
	"log"
	"net/http"
	"strings"
)

func AttachAccountRecoveryHandler(m *http.ServeMux, a authgo.Authenticator, ts *template.Template) {
	m.Handle("/account-recovery", handler.Log(AccountRecovery(a, ts)))
	m.Handle("/account-recovery-verification", handler.Log(AccountRecoveryVerification(a, ts)))
}

func AccountRecovery(a authgo.Authenticator, ts *template.Template) http.Handler {
	ev := a.EmailVerifier()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if a := a.CurrentAccount(w, r); a != nil {
			// Already signed in
			redirect.Account(w, r)
			return
		}
		token, email, _, _, errmsg := a.CurrentAccountRecoverySession(r)
		// log.Println("CurrentAccountRecoverySession", token, email, username, challenge, errmsg)
		switch r.Method {
		case "GET":
			if token == "" {
				t, err := a.NewAccountRecoverySession()
				// log.Println("NewAccountRecoverySession", t, err)
				if err != nil {
					log.Println(err)
					http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
					return
				}
				token = t
				http.SetCookie(w, authgo.NewAccountRecoverySessionCookie(token))
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
			a.SetAccountRecoverySessionError(token, "")

			email := strings.TrimSpace(r.FormValue("email"))

			if err := a.SetAccountRecoverySessionEmail(token, email); err != nil {
				log.Println(err)
				a.SetAccountRecoverySessionError(token, err.Error())
				redirect.AccountRecovery(w, r)
				return
			}

			// Check valid email
			if err := authgo.ValidateEmail(email); err != nil {
				log.Println(err)
				a.SetAccountRecoverySessionError(token, err.Error())
				redirect.AccountRecovery(w, r)
				return
			}

			// Get username associated with email
			username, err := a.LookupUsername(email)
			if err != nil {
				log.Println(err)
				a.SetAccountRecoverySessionError(token, err.Error())
				redirect.AccountRecovery(w, r)
				return
			}

			if err := a.SetAccountRecoverySessionUsername(token, username); err != nil {
				log.Println(err)
				a.SetAccountRecoverySessionError(token, err.Error())
				redirect.AccountRecovery(w, r)
				return
			}

			code, err := ev.VerifyEmail(email)
			// log.Println("VerifyEmail", code, err)
			if err != nil {
				log.Println(err)
				a.SetAccountRecoverySessionError(token, err.Error())
				redirect.AccountRecovery(w, r)
				return
			}
			if err := a.SetAccountRecoverySessionChallenge(token, code); err != nil {
				log.Println(err)
				a.SetAccountRecoverySessionError(token, err.Error())
				redirect.AccountRecovery(w, r)
				return
			}

			redirect.AccountRecoveryVerification(w, r)
		}
	})
}

func AccountRecoveryVerification(a authgo.Authenticator, ts *template.Template) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, _, username, challenge, errmsg := a.CurrentAccountRecoverySession(r)
		// log.Println("CurrentAccountRecoverySession", token, email, username, challenge, errmsg)
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
			a.SetAccountRecoverySessionError(token, "")

			if strings.TrimSpace(r.FormValue("verification")) != challenge {
				a.SetAccountRecoverySessionError(token, authgo.ErrIncorrectEmailVerification.Error())
				redirect.AccountRecoveryVerification(w, r)
				return
			}

			token, err := a.NewSignInSession(username)
			// log.Println("NewSignInSession", token, err)
			if err != nil {
				log.Println(err)
				http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
				return
			}

			http.SetCookie(w, authgo.NewSignInSessionCookie(token))

			redirect.AccountPassword(w, r)
		}
	})
}
