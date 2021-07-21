package handler

import (
	"aletheiaware.com/authgo"
	"aletheiaware.com/authgo/redirect"
	"html/template"
	"log"
	"net/http"
	"strings"
)

func SignIn(a authgo.Authenticator, ts *template.Template) http.Handler {
	am := a.AccountManager()
	sm := a.SessionManager()
	ev := a.EmailVerifier()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, username, authenticated, errmsg := authgo.CurrentSignIn(sm, r)
		// log.Println("CurrentSignIn", token, username, authenticated, errmsg)
		switch r.Method {
		case "GET":
			if token == "" {
				t, err := sm.NewSignIn("")
				// log.Println("NewSignIn", t, err)
				if err != nil {
					log.Println(err)
					http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
					return
				}
				token = t
				http.SetCookie(w, authgo.NewSignInCookie(token))
			}
			if authenticated {
				// Already signed in
				redirect.Account(w, r)
				return
			}
			data := struct {
				Username string
				Error    string
			}{
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
			sm.SetSignInError(token, "")

			username := strings.TrimSpace(r.FormValue("username"))
			password := []byte(strings.TrimSpace(r.FormValue("password")))

			if err := sm.SetSignInUsername(token, username); err != nil {
				log.Println(err)
				sm.SetSignInError(token, err.Error())
				redirect.SignIn(w, r)
				return
			}

			account, err := am.Authenticate(username, password)
			// log.Println("AuthenticateAccount", account, err)
			if err != nil {
				log.Println(err)
				sm.SetSignInError(token, err.Error())
				redirect.SignIn(w, r)
				return
			}

			if err := sm.SetSignInAuthenticated(token, true); err != nil {
				log.Println(err)
				sm.SetSignInError(token, err.Error())
				redirect.SignIn(w, r)
				return
			}

			if !am.IsEmailVerified(account.Email) {
				token, err := sm.NewSignUp()
				// log.Println("NewSignUp", token, err)
				if err != nil {
					log.Println(err)
					http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
					return
				}
				if err := sm.SetSignUpIdentity(token, account.Email, account.Username); err != nil {
					log.Println(err)
					http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
				}

				http.SetCookie(w, authgo.NewSignUpCookie(token))

				code, err := ev.VerifyEmail(account.Email)
				// log.Println("VerifyEmail", code, err)
				if err != nil {
					log.Println(err)
					sm.SetSignUpError(token, err.Error())
					redirect.SignIn(w, r)
					return
				}
				if err := sm.SetSignUpChallenge(token, code); err != nil {
					log.Println(err)
					sm.SetSignUpError(token, err.Error())
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
