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

func AttachSignUpHandler(m *http.ServeMux, a authgo.Authenticator, ts *template.Template) {
	m.Handle("/sign-up", handler.Log(SignUp(a, ts)))
	m.Handle("/sign-up-verification", handler.Log(SignUpVerification(a, ts)))
}

func SignUp(a authgo.Authenticator, ts *template.Template) http.Handler {
	ev := a.EmailVerifier()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if a := a.CurrentAccount(w, r); a != nil {
			// Already signed in
			redirect.Account(w, r)
			return
		}
		token, email, username, _, errmsg := a.CurrentSignUpSession(r)
		// log.Println("CurrentSignUpSession", token, email, username, challenge, errmsg)
		switch r.Method {
		case "GET":
			if token == "" {
				t, err := a.NewSignUpSession()
				// log.Println("NewSignUpSession", t, err)
				if err != nil {
					log.Println(err)
					http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
					return
				}
				token = t
				http.SetCookie(w, authgo.NewSignUpSessionCookie(token))
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
			a.SetSignUpSessionError(token, "")

			email := strings.TrimSpace(r.FormValue("email"))
			username := strings.TrimSpace(r.FormValue("username"))
			password := []byte(strings.TrimSpace(r.FormValue("password")))
			confirmation := []byte(strings.TrimSpace(r.FormValue("confirmation")))

			// Check valid email
			if err := authgo.ValidateEmail(email); err != nil {
				log.Println(err)
				a.SetSignUpSessionError(token, err.Error())
				redirect.SignUp(w, r)
				return
			}

			// Check valid username
			if err := authgo.ValidateUsername(username); err != nil {
				log.Println(err)
				a.SetSignUpSessionError(token, err.Error())
				redirect.SignUp(w, r)
				return
			}

			if err := a.SetSignUpSessionIdentity(token, email, username); err != nil {
				log.Println(err)
				a.SetSignUpSessionError(token, err.Error())
				redirect.SignUp(w, r)
				return
			}

			// Check valid password and matching confirm
			if err := authgo.ValidatePassword(password); err != nil {
				log.Println(err)
				a.SetSignUpSessionError(token, err.Error())
				redirect.SignUp(w, r)
				return
			}
			if err := authgo.MatchPasswords(password, confirmation); err != nil {
				log.Println(err)
				a.SetSignUpSessionError(token, err.Error())
				redirect.SignUp(w, r)
				return
			}

			_, err := a.NewAccount(email, username, password)
			// log.Println("NewAccount", acc, err)
			if err != nil {
				log.Println(err)
				a.SetSignUpSessionError(token, err.Error())
				redirect.SignUp(w, r)
				return
			}

			code, err := ev.VerifyEmail(email)
			// log.Println("VerifyEmail", code, err)
			if err != nil {
				log.Println(err)
				a.SetSignUpSessionError(token, err.Error())
				redirect.SignUp(w, r)
				return
			}
			if err := a.SetSignUpSessionChallenge(token, code); err != nil {
				log.Println(err)
				a.SetSignUpSessionError(token, err.Error())
				redirect.SignUp(w, r)
				return
			}

			redirect.SignUpVerification(w, r)
		}
	})
}

func SignUpVerification(a authgo.Authenticator, ts *template.Template) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, email, username, challenge, errmsg := a.CurrentSignUpSession(r)
		// log.Println("CurrentSignUpSession", token, email, username, challenge, errmsg)
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
			a.SetSignUpSessionError(token, "")

			if strings.TrimSpace(r.FormValue("verification")) != challenge {
				a.SetSignUpSessionError(token, authgo.ErrEmailVerificationIncorrect.Error())
				redirect.SignUpVerification(w, r)
				return
			}

			if err := a.SetEmailVerified(email, true); err != nil {
				log.Println(err)
				http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
				return
			}

			token, err := a.NewSignInSession(username)
			// log.Println("NewSignInSession", token, err)
			if err != nil {
				log.Println(err)
				http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
				return
			}

			if err := a.SetSignInSessionAuthenticated(token, true); err != nil {
				log.Println(err)
				http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
				return
			}

			http.SetCookie(w, authgo.NewSignInSessionCookie(token))

			redirect.Account(w, r)
		}
	})
}
