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

func AttachSignInHandler(m *http.ServeMux, a authgo.Authenticator, ts *template.Template) {
	m.Handle("/sign-in", handler.Log(SignIn(a, ts)))
}

func SignIn(a authgo.Authenticator, ts *template.Template) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, username, authenticated, _, errmsg := a.CurrentSignInSession(r)
		// log.Println("CurrentSignInSession", token, username, authenticated, created, errmsg)
		switch r.Method {
		case "GET":
			if token == "" {
				t, err := a.NewSignInSession("")
				// log.Println("NewSignInSession", t, err)
				if err != nil {
					log.Println(err)
					http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
					return
				}
				token = t
				http.SetCookie(w, a.NewSignInSessionCookie(token))
			}
			if authenticated {
				// Already signed in
				redirect.Account(w, r)
				return
			}
			data := struct {
				Live     bool
				Username string
				Error    string
			}{
				Live:     netgo.IsLive(),
				Username: username,
				Error:    errmsg,
			}
			if err := ts.ExecuteTemplate(w, "sign-in.go.html", data); err != nil {
				log.Println(err)
				return
			}
		case "POST":
			if token == "" {
				redirect.SignIn(w, r)
				return
			}
			a.SetSignInSessionError(token, "")

			username := strings.TrimSpace(r.FormValue("username"))
			password := []byte(strings.TrimSpace(r.FormValue("password")))

			if err := a.SetSignInSessionUsername(token, username); err != nil {
				log.Println(err)
				a.SetSignInSessionError(token, err.Error())
				redirect.SignIn(w, r)
				return
			}

			account, err := a.AuthenticateAccount(username, password)
			// log.Println("AuthenticateAccount", account, err)
			if err != nil {
				log.Println(err)
				a.SetSignInSessionError(token, err.Error())
				redirect.SignIn(w, r)
				return
			}

			if err := a.SetSignInSessionAuthenticated(token, true); err != nil {
				log.Println(err)
				a.SetSignInSessionError(token, err.Error())
				redirect.SignIn(w, r)
				return
			}

			if !a.IsEmailVerified(account.Email) {
				token, err := a.NewSignUpSession()
				// log.Println("NewSignUpSession", token, err)
				if err != nil {
					log.Println(err)
					http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
					return
				}
				if err := a.SetSignUpSessionIdentity(token, account.Email, account.Username); err != nil {
					log.Println(err)
					http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
				}

				http.SetCookie(w, a.NewSignUpSessionCookie(token))

				code, err := a.EmailVerifier().Verify(account.Email, account.Username)
				// log.Println("Verify", account.Email, account.Username, code, err)
				if err != nil {
					log.Println(err)
					a.SetSignUpSessionError(token, err.Error())
					redirect.SignIn(w, r)
					return
				}
				if err := a.SetSignUpSessionChallenge(token, code); err != nil {
					log.Println(err)
					a.SetSignUpSessionError(token, err.Error())
					redirect.SignIn(w, r)
					return
				}
				redirect.SignUpVerification(w, r)
				return
			}
			redirect.Account(w, r)
		}
	})
}
