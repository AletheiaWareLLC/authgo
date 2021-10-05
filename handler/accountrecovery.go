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

func AttachAccountRecoveryHandler(m *http.ServeMux, a authgo.Authenticator, ts *template.Template) {
	m.Handle("/account-recovery", handler.Log(AccountRecovery(a, ts)))
	m.Handle("/account-recovery-verification", handler.Log(AccountRecoveryVerification(a, ts)))
}

func AccountRecovery(a authgo.Authenticator, ts *template.Template) http.Handler {
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
			data := struct {
				Live bool
				Email,
				Error string
			}{
				Live:  netgo.IsLive(),
				Email: email,
				Error: errmsg,
			}
			if err := ts.ExecuteTemplate(w, "account-recovery.go.html", data); err != nil {
				log.Println(err)
				return
			}
		case "POST":
			if token == "" {
				t, err := a.NewAccountRecoverySession()
				// log.Println("NewAccountRecoverySession", t, err)
				if err != nil {
					log.Println(err)
					http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
					return
				}
				token = t
				http.SetCookie(w, a.NewAccountRecoverySessionCookie(token))
			}

			email := strings.TrimSpace(r.FormValue("email"))

			if err := accountRecovery(a, token, email); err != nil {
				log.Println(err)
				a.SetAccountRecoverySessionError(token, err.Error())
				redirect.AccountRecovery(w, r)
				return
			}

			a.SetAccountRecoverySessionError(token, "")

			redirect.AccountRecoveryVerification(w, r)
		}
	})
}

func accountRecovery(a authgo.Authenticator, token, email string) error {
	if err := a.SetAccountRecoverySessionEmail(token, email); err != nil {
		return err
	}

	// Check valid email
	if err := authgo.ValidateEmail(email); err != nil {
		return err
	}

	// Get username associated with email
	username, err := a.LookupUsernameForEmail(email)
	if err != nil {
		return err
	}

	if err := a.SetAccountRecoverySessionUsername(token, username); err != nil {
		return err
	}

	code, err := a.EmailVerifier().Verify(email, username)
	// log.Println("Verify", email, username, code, err)
	if err != nil {
		return err
	}
	if err := a.SetAccountRecoverySessionChallenge(token, code); err != nil {
		return err
	}
	return nil
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
				Live bool
				Username,
				Error string
			}{
				Live:     netgo.IsLive(),
				Username: username,
				Error:    errmsg,
			}
			if err := ts.ExecuteTemplate(w, "account-recovery-verification.go.html", data); err != nil {
				log.Println(err)
				return
			}
		case "POST":
			verification := strings.TrimSpace(r.FormValue("verification"))

			if err := accountRecoveryVerification(challenge, verification); err != nil {
				a.SetAccountRecoverySessionError(token, err.Error())
				redirect.AccountRecoveryVerification(w, r)
				return
			}

			a.SetAccountRecoverySessionError(token, "")

			token, err := a.NewSignInSession(username)
			// log.Println("NewSignInSession", token, err)
			if err != nil {
				log.Println(err)
				http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
				return
			}

			http.SetCookie(w, a.NewSignInSessionCookie(token))

			redirect.AccountPassword(w, r)
		}
	})
}

func accountRecoveryVerification(challenge, verification string) error {
	if verification != challenge {
		return authgo.ErrEmailVerificationIncorrect
	}
	return nil
}
