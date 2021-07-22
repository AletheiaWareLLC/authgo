package handler

import (
	"aletheiaware.com/authgo"
	"aletheiaware.com/authgo/redirect"
	"html/template"
	"log"
	"net/http"
	"strings"
)

func SignUp(a authgo.Authenticator, ts *template.Template) http.Handler {
	am := a.AccountManager()
	sm := a.SessionManager()
	ev := a.EmailVerifier()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if a := a.CurrentAccount(w, r); a != nil {
			// Already signed in
			redirect.Account(w, r)
			return
		}
		token, email, username, _, errmsg := authgo.CurrentSignUp(sm, r)
		// log.Println("CurrentSignUp", token, email, username, challenge, errmsg)
		switch r.Method {
		case "GET":
			if token == "" {
				t, err := sm.NewSignUp()
				// log.Println("NewSignUp", t, err)
				if err != nil {
					log.Println(err)
					http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
					return
				}
				token = t
				http.SetCookie(w, authgo.NewSignUpCookie(token))
			}
			data := struct {
				Email,
				Username,
				Error string
			}{
				Email:    email,
				Username: username,
				Error:    errmsg,
			}
			if err := ts.ExecuteTemplate(w, "sign-up.go.html", data); err != nil {
				log.Println(err)
				return
			}
		case "POST":
			if token == "" {
				redirect.SignUp(w, r)
				return
			}
			sm.SetSignUpError(token, "")

			email := strings.TrimSpace(r.FormValue("email"))
			username := strings.TrimSpace(r.FormValue("username"))
			password := []byte(strings.TrimSpace(r.FormValue("password")))
			confirmation := []byte(strings.TrimSpace(r.FormValue("confirmation")))

			if err := sm.SetSignUpIdentity(token, email, username); err != nil {
				log.Println(err)
				sm.SetSignUpError(token, err.Error())
				redirect.SignUp(w, r)
				return
			}

			// Check valid email
			if err := authgo.ValidateEmail(email); err != nil {
				log.Println(err)
				sm.SetSignUpError(token, err.Error())
				redirect.SignUp(w, r)
				return
			}

			// Check valid username
			if err := authgo.ValidateUsername(username); err != nil {
				log.Println(err)
				sm.SetSignUpError(token, err.Error())
				redirect.SignUp(w, r)
				return
			}

			// Check valid password and matching confirm
			if err := authgo.ValidatePassword(password); err != nil {
				log.Println(err)
				sm.SetSignUpError(token, err.Error())
				redirect.SignUp(w, r)
				return
			}
			if err := authgo.MatchPasswords(password, confirmation); err != nil {
				log.Println(err)
				sm.SetSignUpError(token, err.Error())
				redirect.SignUp(w, r)
				return
			}

			_, err := am.New(email, username, password)
			// log.Println("NewAccount", acc, err)
			if err != nil {
				log.Println(err)
				sm.SetSignUpError(token, err.Error())
				redirect.SignUp(w, r)
				return
			}

			code, err := ev.VerifyEmail(email)
			// log.Println("VerifyEmail", code, err)
			if err != nil {
				log.Println(err)
				sm.SetSignUpError(token, err.Error())
				redirect.SignUp(w, r)
				return
			}
			if err := sm.SetSignUpChallenge(token, code); err != nil {
				log.Println(err)
				sm.SetSignUpError(token, err.Error())
				redirect.SignUp(w, r)
				return
			}

			redirect.SignUpVerification(w, r)
		}
	})
}

func SignUpVerification(a authgo.Authenticator, ts *template.Template) http.Handler {
	am := a.AccountManager()
	sm := a.SessionManager()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, email, username, challenge, errmsg := authgo.CurrentSignUp(sm, r)
		// log.Println("CurrentSignUp", token, email, username, challenge, errmsg)
		if token == "" {
			redirect.SignUp(w, r)
			return
		}
		switch r.Method {
		case "GET":
			data := struct {
				Error string
			}{
				Error: errmsg,
			}
			if err := ts.ExecuteTemplate(w, "sign-up-verification.go.html", data); err != nil {
				log.Println(err)
				return
			}
		case "POST":
			sm.SetSignUpError(token, "")

			if strings.TrimSpace(r.FormValue("verification")) != challenge {
				sm.SetSignUpError(token, authgo.ErrIncorrectEmailVerification.Error())
				redirect.SignUpVerification(w, r)
				return
			}

			if err := am.SetEmailVerified(email, true); err != nil {
				log.Println(err)
				http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
				return
			}

			token, err := sm.NewSignIn(username)
			// log.Println("NewSignIn", token, err)
			if err != nil {
				log.Println(err)
				http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
				return
			}

			if err := sm.SetSignInAuthenticated(token, true); err != nil {
				log.Println(err)
				http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
				return
			}

			http.SetCookie(w, authgo.NewSignInCookie(token))

			redirect.Index(w, r)
		}
	})
}
