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

func AttachSignUpHandler(m *http.ServeMux, a authgo.Authenticator, ts *template.Template) {
	m.Handle("/sign-up", handler.Log(SignUp(a, ts)))
	m.Handle("/sign-up-verification", handler.Log(SignUpVerification(a, ts)))
}

func SignUp(a authgo.Authenticator, ts *template.Template) http.Handler {
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
				http.SetCookie(w, a.NewSignUpSessionCookie(token))
			}
			data := struct {
				Live bool
				Email,
				Username,
				Error string
			}{
				Live:     netgo.IsLive(),
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

			email := strings.TrimSpace(r.FormValue("email"))
			username := strings.TrimSpace(r.FormValue("username"))
			password := []byte(strings.TrimSpace(r.FormValue("password")))
			confirmation := []byte(strings.TrimSpace(r.FormValue("confirmation")))

			if err := signUp(a, token, email, username, password, confirmation); err != nil {
				log.Println(err)
				a.SetSignUpSessionError(token, err.Error())
				redirect.SignUp(w, r)
				return
			}
			a.SetSignUpSessionError(token, "")

			redirect.SignUpVerification(w, r)
		}
	})
}

func signUp(a authgo.Authenticator, token, email, username string, password, confirmation []byte) error {
	// Check valid email
	if err := authgo.ValidateEmail(email); err != nil {
		return err
	}

	// Check valid username
	if err := authgo.ValidateUsername(username); err != nil {
		return err
	}

	if err := a.SetSignUpSessionIdentity(token, email, username); err != nil {
		return err
	}

	// Check valid password and matching confirm
	if err := authgo.ValidatePassword(password); err != nil {
		return err
	}
	if err := authgo.MatchPasswords(password, confirmation); err != nil {
		return err
	}

	_, err := a.NewAccount(email, username, password)
	// log.Println("NewAccount", acc, err)
	if err != nil {
		return err
	}

	code, err := a.EmailVerifier().Verify(email, username)
	// log.Println("VerifyEmail", email, username, code, err)
	if err != nil {
		return err
	}
	if err := a.SetSignUpSessionChallenge(token, code); err != nil {
		return err
	}
	return nil
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
				Live  bool
				Error string
			}{
				Live:  netgo.IsLive(),
				Error: errmsg,
			}
			if err := ts.ExecuteTemplate(w, "sign-up-verification.go.html", data); err != nil {
				log.Println(err)
				return
			}
		case "POST":
			verification := strings.TrimSpace(r.FormValue("verification"))

			if err := signUpVerification(challenge, verification); err != nil {
				a.SetSignUpSessionError(token, err.Error())
				redirect.SignUpVerification(w, r)
				return
			}

			a.SetSignUpSessionError(token, "")

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

			http.SetCookie(w, a.NewSignInSessionCookie(token))

			redirect.Account(w, r)
		}
	})
}

func signUpVerification(challenge, verification string) error {
	if verification != challenge {
		return authgo.ErrEmailVerificationIncorrect
	}
	return nil
}
