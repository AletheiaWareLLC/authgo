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

func AttachSignInHandler(m *http.ServeMux, a authgo.Authenticator, ts *template.Template) {
	m.Handle("/sign-in", handler.Log(handler.Compress(SignIn(a, ts))))
}

func SignIn(a authgo.Authenticator, ts *template.Template) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, username, authenticated, _, errmsg := a.CurrentSignInSession(r)
		// log.Println("CurrentSignInSession", token, username, authenticated, created, errmsg)
		next, err := url.QueryUnescape(strings.TrimSpace(r.FormValue("next")))
		if err != nil {
			log.Println(err)
			http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
			return
		}
		switch r.Method {
		case "GET":
			if authenticated {
				// Already signed in
				redirect.Account(w, r)
				return
			}
			data := struct {
				Live     bool
				Username string
				Error    string
				Next     string
			}{
				Live:     netgo.IsLive(),
				Username: username,
				Error:    errmsg,
				Next:     next,
			}
			if err := ts.ExecuteTemplate(w, "sign-in.go.html", data); err != nil {
				log.Println(err)
				return
			}
		case "POST":
			username := strings.TrimSpace(r.FormValue("username"))
			password := []byte(strings.TrimSpace(r.FormValue("password")))

			if token == "" {
				t, err := a.NewSignInSession(username, false)
				// log.Println("NewSignInSession", t, err)
				if err != nil {
					log.Println(err)
					http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
					return
				}
				token = t
				http.SetCookie(w, a.NewSignInSessionCookie(token))
			} else {
				if err := a.SetSignInSessionUsername(token, username); err != nil {
					log.Println(err)
					a.SetSignInSessionError(token, err.Error())
					redirect.SignIn(w, r, next)
					return
				}
				a.SetSignInSessionError(token, "")
			}

			account, err := a.AuthenticateAccount(username, password)
			// log.Println("AuthenticateAccount", account, err)
			if err != nil {
				log.Println(err)
				a.SetSignInSessionError(token, err.Error())
				redirect.SignIn(w, r, next)
				return
			}

			if err := a.SetSignInSessionAuthenticated(token, true); err != nil {
				log.Println(err)
				a.SetSignInSessionError(token, err.Error())
				redirect.SignIn(w, r, next)
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
					return
				}

				http.SetCookie(w, a.NewSignUpSessionCookie(token))

				code, err := a.EmailVerifier().Verify(account.Email, account.Username)
				// log.Println("Verify", account.Email, account.Username, code, err)
				if err != nil {
					log.Println(err)
					a.SetSignUpSessionError(token, err.Error())
					redirect.SignIn(w, r, next)
					return
				}
				if err := a.SetSignUpSessionChallenge(token, code); err != nil {
					log.Println(err)
					a.SetSignUpSessionError(token, err.Error())
					redirect.SignIn(w, r, next)
					return
				}
				redirect.SignUpVerification(w, r, next)
				return
			}
			if next == "" {
				redirect.Account(w, r)
			} else {
				http.Redirect(w, r, next, http.StatusFound)
			}
		}
	})
}
